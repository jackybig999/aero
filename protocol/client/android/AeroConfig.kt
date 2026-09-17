package com.aero.vpn

/** Same JSON keys as iOS AeroTunnelConfig / Win subscription. */
data class AeroTunnelConfig(
    var serverAddress: String = "",
    var token: String = "",
    var sni: String = "cdn-aero.com",
    var fingerprint: String = "chrome",
    var splitEnabled: Boolean = true,
    var mtu: Int = 1420,
    var dns: List<String> = listOf("223.5.5.5", "8.8.8.8"),
    /** Edge IPv4; VpnService.protect + excludeRoute. Same as Win ProtectHostRoute. */
    var edgeIPv4: String = "",
    var subscriptionUrl: String = ""
)
