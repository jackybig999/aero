package com.aero.vpn

import org.json.JSONObject

/**
 * Kotlin side of internal/android. After gomobile bind, replace the
 * placeholders with the generated `android.Android` class.
 *
 * Keep this file as the only JNI/gomobile callsite so Win/iOS/Android
 * stay on one JSON config.
 */
object AeroBridge {
    fun startTunnel(config: AeroTunnelConfig): Result<Unit> {
        val json = JSONObject()
            .put("serverAddress", config.serverAddress)
            .put("token", config.token)
            .put("sni", config.sni)
            .put("fingerprint", config.fingerprint)
            .put("splitEnabled", config.splitEnabled)
            .put("mtu", config.mtu)
            .put("dns", config.dns)
            .put("subscriptionUrl", config.subscriptionUrl)
            .put("edgeIPv4", config.edgeIPv4)
            .toString()
        return try {
            AndroidStart(json)
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    fun startTunnelFD(fd: Int, config: AeroTunnelConfig): Result<Unit> {
        val json = JSONObject()
            .put("serverAddress", config.serverAddress)
            .put("token", config.token)
            .put("sni", config.sni)
            .put("fingerprint", config.fingerprint)
            .put("splitEnabled", config.splitEnabled)
            .put("mtu", config.mtu)
            .put("dns", config.dns)
            .put("subscriptionUrl", config.subscriptionUrl)
            .put("edgeIPv4", config.edgeIPv4)
            .toString()
        return try {
            AndroidStartFD(fd, json)
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    fun stopTunnel() {
        AndroidStop()
    }

    fun handlePacket(packet: ByteArray) {
        AndroidHandlePacket(packet)
    }

    fun registerPacketCallback(callback: (ByteArray) -> Unit) {
        AndroidRegisterPacketCallback(callback)
    }

    fun networkChanged(physicalIP: String) {
        AndroidNetworkChanged(physicalIP)
    }

    fun stats(): String {
        return AndroidStats()
    }
}

/** Filled by gomobile; stubs so this file type-checks before bind. */
private fun AndroidStart(json: String) {}
private fun AndroidStartFD(fd: Int, json: String) {}
private fun AndroidStop() {}
private fun AndroidHandlePacket(packet: ByteArray) {}
private fun AndroidRegisterPacketCallback(cb: (ByteArray) -> Unit) {}
private fun AndroidNetworkChanged(physicalIP: String) {}
private fun AndroidStats(): String = "{}"
