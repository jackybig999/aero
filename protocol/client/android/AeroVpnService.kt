package com.aero.vpn

import android.content.Intent
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.net.Inet4Address

/**
 * Windows TUN equivalent: global capture, mixed port is desktop-only.
 * protect(fd) == ProtectHostRoute. NetworkCallback == monitor physical change.
 */
class AeroVpnService : VpnService() {

    private var tun: ParcelFileDescriptor? = null
    private var reader: Thread? = null
    private var writer: java.io.FileOutputStream? = null
    private var callback: ConnectivityManager.NetworkCallback? = null
    private var lastPhysical: String = ""

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopSelf()
            return START_NOT_STICKY
        }
        if (!establishTun()) {
            stopSelf()
            return START_NOT_STICKY
        }
        val pfd = tun ?: run {
            stopSelf()
            return START_NOT_STICKY
        }
        val outs = java.io.FileOutputStream(pfd.fileDescriptor)
        writer = outs
        AeroBridge.registerPacketCallback { pkt ->
            try {
                outs.write(pkt)
            } catch (_: Exception) {
            }
        }

        val cfg = AeroTunnelConfig(
            serverAddress = intent?.getStringExtra("serverAddress") ?: "",
            token = intent?.getStringExtra("token") ?: "",
            edgeIPv4 = intent?.getStringExtra("edgeIPv4") ?: "",
            subscriptionUrl = intent?.getStringExtra("subscriptionUrl") ?: ""
        )
        AeroBridge.startTunnel(cfg).onFailure {
            stopSelf()
            return START_NOT_STICKY
        }
        startReader()
        watchPhysicalPath()
        return START_STICKY
    }

    override fun onRevoke() {
        teardown()
        super.onRevoke()
    }

    override fun onDestroy() {
        teardown()
        super.onDestroy()
    }

    private fun establishTun(): Boolean {
        val b = Builder()
            .setSession("AERO")
            .setMtu(1420)
            .addAddress("10.88.0.2", 24)
            .addDnsServer("8.8.8.8")
            .addRoute("0.0.0.0", 0)
        val edge = intentEdgeIPv4()
        if (edge.isNotEmpty() && Build.VERSION.SDK_INT >= 33) {
            try {
                val prefix = android.net.IpPrefix(java.net.InetAddress.getByName(edge), 32)
                b.excludeRoute(prefix)
            } catch (_: Exception) {
            }
        }
        tun = try {
            b.establish()
        } catch (_: Exception) {
            null
        }
        return tun != null
    }

    private fun startReader() {
        val pfd = tun ?: return
        reader = Thread {
            val ins = FileInputStream(pfd.fileDescriptor)
            val buf = ByteArray(4096)
            while (!Thread.interrupted()) {
                val n = try {
                    ins.read(buf)
                } catch (_: Exception) {
                    break
                }
                if (n <= 0) break
                AeroBridge.handlePacket(buf.copyOf(n))
            }
        }.also { it.start() }
    }

    private fun watchPhysicalPath() {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) = emitIfPhysicalChanged(cm, network)
            override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) =
                emitIfPhysicalChanged(cm, network)
        }
        callback = cb
        cm.registerDefaultNetworkCallback(cb)
    }

    private fun emitIfPhysicalChanged(cm: ConnectivityManager, network: Network) {
        val caps = cm.getNetworkCapabilities(network) ?: return
        if (!caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) &&
            !caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) &&
            !caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)
        ) {
            return
        }
        val lp = cm.getLinkProperties(network) ?: return
        val ip = lp.linkAddresses
            .mapNotNull { it.address as? Inet4Address }
            .firstOrNull { !it.isLoopbackAddress }
            ?.hostAddress ?: return
        if (ip == lastPhysical) return
        lastPhysical = ip
        AeroBridge.networkChanged(ip)
    }

    private fun teardown() {
        callback?.let {
            try {
                getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(it)
            } catch (_: Exception) {
            }
        }
        callback = null
        reader?.interrupt()
        reader = null
        AeroBridge.stopTunnel()
        try {
            writer?.close()
        } catch (_: Exception) {
        }
        writer = null
        try {
            tun?.close()
        } catch (_: Exception) {
        }
        tun = null
    }

    private fun intentEdgeIPv4(): String = ""

    companion object {
        const val ACTION_STOP = "com.aero.vpn.STOP"
    }
}
