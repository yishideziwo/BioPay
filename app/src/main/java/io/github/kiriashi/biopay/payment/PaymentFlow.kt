/*
 * BioPay - biometric payment assistance for supported payment apps.
 * Copyright (C) 2026 kiriashi
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package io.github.kiriashi.biopay.payment

import android.app.Activity
import android.view.View
import android.view.ViewGroup
import io.github.kiriashi.biopay.apps.PaymentApp
import io.github.kiriashi.biopay.apps.shared.KeyboardMode
import io.github.kiriashi.biopay.biometric.BiometricAuth
import io.github.kiriashi.biopay.core.log.ModuleLog
import io.github.kiriashi.biopay.core.util.MainTasks
import io.github.kiriashi.biopay.core.util.findActivity
import io.github.kiriashi.biopay.runtime.AppRuntime
import io.github.kiriashi.biopay.storage.PasswordCipher
import java.lang.ref.WeakReference

class PaymentFlow(private val state: AppRuntime) {
    private val attachLock = Any()
    private var attachListener: KeyboardAttachListener? = null
    private var attachedViewRef: WeakReference<ViewGroup>? = null
    private val setupLock = Any()
    private val tasks = MainTasks()
    // 预生成的解密 Cipher：在键盘出现时后台生成，attach 后直接用于弹窗，省掉 Keystore 初始化延迟
    @Volatile private var preparedOperation: PasswordCipher.DecryptOperation? = null
    private var preparedSessionId: Long = 0L

    fun setupBiometricAuth(
        keyboardView: ViewGroup, encodedPassword: String,
        hostActivity: Activity? = null, startImmediately: Boolean = true,
        keyboardMode: KeyboardMode = KeyboardMode.APP
    ): Boolean {
        if (state.isClosed) return false
        val config = state.prefs.activeConfig()?.takeIf { it.encryptedPassword == encodedPassword } ?: return false
        val (sessionId, shouldTrigger) = synchronized(setupLock) {
            val alreadyInProgress = state.session.isAuthenticationInProgress() ||
                PasswordAutoInput.isInProgress(state.session.currentSessionId())
            val id = if (alreadyInProgress) state.session.currentSessionId() else state.session.beginSession()
            removeListenersFromOldView()

            state.session.bindKeyboard(keyboardView, hostActivity ?: keyboardView.context.findActivity(), config, keyboardMode)

            // Visual payment screens are watched by VisualPaymentMonitor. Reattaching
            // their keyboard must not start a second automatic prompt after cancel.
            if (startImmediately && state.adapter.app == PaymentApp.WECHAT) {
                // 预生成 Cipher：键盘一出现就后台建密钥，缩短 attach 后指纹弹窗的延迟
                val sid = id
                val pkg = state.adapter.app.packageName
                state.paymentWorker.submit(
                    work = { PasswordCipher.createDecryptOperation(encodedPassword, pkg) },
                    discard = { it?.ciphertext?.fill(0) }
                ) { result ->
                    val op = result.getOrNull()
                    if (op != null) {
                        synchronized(attachLock) {
                            if (state.session.isCurrentSession(sid)) {
                                preparedOperation?.ciphertext?.fill(0)
                                preparedOperation = op
                                preparedSessionId = sid
                            } else {
                                op.ciphertext.fill(0)
                            }
                        }
                    }
                }
                synchronized(attachLock) {
                    val listener = attachListener ?: KeyboardAttachListener().also { attachListener = it }
                    listener.keyboardView = keyboardView
                    listener.sessionId = id
                }
            }

            id to !alreadyInProgress
        }

        if (!startImmediately) return true
        if (state.adapter.app == PaymentApp.WECHAT) {
            val listener = synchronized(attachLock) { attachListener } ?: return false
            keyboardView.addOnAttachStateChangeListener(listener)
            synchronized(attachLock) { attachedViewRef = WeakReference(keyboardView) }
        }
        if (!shouldTrigger) return true
        return BiometricAuth.triggerBiometricAuth(keyboardView, encodedPassword, state, sessionId)
    }

    fun toggleBetweenBiometricAndKeyboard() {
        if (state.isClosed) return
        try {
            val keyboardView = state.session.getCurrentKeyboardView() ?: return

            if (state.session.isAuthenticationInProgress()) {
                state.session.cancelAuthentication()
            } else if (!PasswordAutoInput.isInProgress(state.session.currentSessionId())) {
                val config = state.prefs.activeConfig() ?: return
                state.session.bindConfig(config)
                BiometricAuth.triggerBiometricAuth(keyboardView, config.encryptedPassword, state, state.session.currentSessionId())
            }
        } catch (e: Throwable) {
            ModuleLog.d(e) { "toggleBetweenBiometricAndKeyboard failed" }
        }
    }

    fun reset() {
        PasswordAutoInput.cancelPendingRunnables()
        InputMask.reset()
        synchronized(attachLock) {
            attachListener?.let { l ->
                val view = attachedViewRef?.get()
                tasks.onMain { view?.removeOnAttachStateChangeListener(l) }
            }
            attachListener = null
            attachedViewRef = null
        }
    }

    private fun removeListenersFromOldView() {
        synchronized(attachLock) {
            val oldView = attachedViewRef?.get()
            if (oldView != null) {
                attachListener?.let { oldView.removeOnAttachStateChangeListener(it) }
            }
            attachedViewRef = null
        }
    }

    private inner class KeyboardAttachListener : View.OnAttachStateChangeListener {
        private var keyboardViewRef: WeakReference<ViewGroup>? = null
        var keyboardView: ViewGroup?
            get() = keyboardViewRef?.get()
            set(value) { keyboardViewRef = value?.let(::WeakReference) }
        var sessionId: Long = 0L

        override fun onViewAttachedToWindow(view: View) {
            if (state.isClosed || keyboardView !== view || state.session.getCurrentKeyboardView() !== view) return
            keyboardView?.let { kv ->
                if (state.session.isCurrentSession(sessionId) &&
                    !state.session.isAuthenticationInProgress() &&
                    !PasswordAutoInput.isInProgress(sessionId)) {
                    val encoded = state.prefs.activePassword()
                    if (!encoded.isNullOrEmpty()) {
                        val prepared = synchronized(attachLock) {
                            if (preparedSessionId == sessionId) preparedOperation.also { preparedOperation = null } else null
                        }
                        ModuleLog.d { "onViewAttached: triggering auth, view=${kv.hashCode()}, prepared=${prepared != null}" }
                        if (prepared != null) {
                            BiometricAuth.triggerBiometricAuth(kv, encoded, state, sessionId, prepared)
                        } else {
                            BiometricAuth.triggerBiometricAuth(kv, encoded, state, sessionId)
                        }
                    }
                } else {
                    ModuleLog.d { "onViewAttached: biometric in progress, skipping, view=${kv.hashCode()}" }
                }
            }
        }

        override fun onViewDetachedFromWindow(view: View) {
            val detachedView = view as? ViewGroup ?: return
            view.removeOnAttachStateChangeListener(this)
            if (state.session.getCurrentKeyboardView() !== detachedView) return

            InputMask.reset()
            PasswordAutoInput.cancelPendingRunnables()

            if (state.session.isAuthenticationInProgress()) {
                // Payment Activities can recreate the keyboard during authentication.
                ModuleLog.d { "onViewDetached: keeping payment session, view=${detachedView.hashCode()}" }
                return
            }

            ModuleLog.d { "onViewDetached: clearing payment state, view=${detachedView.hashCode()}" }
            state.session.endSession(sessionId)
            keyboardView = null
            sessionId = 0L
        }
    }
}
