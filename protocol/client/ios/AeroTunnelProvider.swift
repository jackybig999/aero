// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// AeroTunnelProvider.swift
// NEPacketTunnelProvider 实现，系统流量拦截入口。
//
// 配置要求：
//   - App Group: group.aero.vpn
//   - UserDefaults suiteName: group.aero.vpn
//   - 需要 NetworkExtension 权限

import NetworkExtension
import Network
import Foundation

/// AERO Packet Tunnel Provider
/// 系统通过此 Provider 将流量转发到 AERO 隧道
public class AeroTunnelProvider: NEPacketTunnelProvider {

    /// 用户选择的分流分类（通过 App UI 设置）
    private var selectedCategories: [String] = []

    /// 排除的 Bundle ID 列表（iOS 16+）
    private var excludedBundleIDs: [String] = []

    /// 隧道配置
    private var tunnelConfig: [String: Any] = [:]

    /// Physical path monitor — same job as Go monitor on Win/mac.
    private var pathMonitor: NWPathMonitor?
    private var lastPathKey: String = ""
    private var applyingSettings = false

    // MARK: - NEPacketTunnelProvider 生命周期

    public override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        // 1. 读取用户配置
        loadUserPreferences()

        // 2. 构建隧道配置
        guard let config = buildTunnelConfig() else {
            completionHandler(AeroBridge.AeroError.invalidConfig)
            return
        }
        self.tunnelConfig = config

        // 3. 设置 VPN 网络配置
        let settings = buildNetworkSettings()

        // 4. iOS 16+ 设置排除应用
        if #available(iOS 16.0, *) {
            settings.excludedApplications = excludedBundleIDs
        }

        setTunnelNetworkSettings(settings) { [weak self] error in
            if let error = error {
                completionHandler(error)
                return
            }

            // 5. 启动 Go 隧道与回包链路
            AeroBridge.shared.registerPacketCallback { [weak self] returnPacket in
                self?.packetFlow.writePackets([returnPacket], withProtocols: [NSNumber(value: AF_INET)])
            }
            let result = AeroBridge.shared.startTunnel(config: config)
            switch result {
            case .success:
                self?.startPacketReading()
                self?.startPathMonitor()
                completionHandler(nil)
            case .failure(let err):
                completionHandler(err)
            }
        }
    }

    public override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        pathMonitor?.cancel()
        pathMonitor = nil
        AeroBridge.shared.stopTunnel()
        completionHandler()
    }

    public override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        // 处理来自主 App 的消息（如规则更新、状态查询）
        guard let dict = try? JSONSerialization.jsonObject(with: messageData) as? [String: Any],
              let action = dict["action"] as? String else {
            completionHandler?(nil)
            return
        }

        switch action {
        case "updateRules":
            if let rules = dict["rules"] as? [[String: Any]] {
                _ = AeroBridge.shared.updateRules(rules: rules)
            }
        case "getStats":
            let stats = AeroBridge.shared.stats()
            let resp = try? JSONSerialization.data(withJSONObject: stats)
            completionHandler?(resp)
        default:
            completionHandler?(nil)
        }
    }

    // MARK: - 数据包处理

    /// 启动循环读取系统转发的 IP 包
    private func startPacketReading() {
        packetFlow.readPackets { [weak self] packets, protocols in
            for (index, packet) in packets.enumerated() {
                // 简单检查：IPv4 且 TCP/UDP 才转发
                guard packet.count >= 20 else { continue }
                let proto = protocols[index]
                if proto == AF_INET || proto == AF_INET6 {
                    AeroBridge.shared.handlePacket(packet)
                }
            }
            // 继续读取下一批
            self?.startPacketReading()
        }
    }

    // MARK: - 配置构建

    /// 从协议配置和用户偏好构建隧道配置
    private func buildTunnelConfig() -> [String: Any]? {
        // 从 NEVPNProtocol 读取配置
        guard let proto = protocolConfiguration as? NETunnelProviderProtocol else {
            return nil
        }

        var config: [String: Any] = [
            "serverAddress": proto.serverAddress ?? "",
            "sni": proto.providerConfiguration?["sni"] as? String ?? "cdn-aero.com",
            "fingerprint": proto.providerConfiguration?["fingerprint"] as? String ?? "chrome",
            "splitEnabled": proto.providerConfiguration?["splitEnabled"] as? Bool ?? true,
            "mtu": proto.providerConfiguration?["mtu"] as? Int ?? 1420,
            "dns": proto.providerConfiguration?["dns"] as? [String] ?? ["223.5.5.5", "8.8.8.8"]
        ]

        // Token 从 keychain 或 App Group 读取（不在协议配置中明文存储）
        if let token = readTokenFromSharedDefaults() {
            config["token"] = token
        }

        // 订阅 URL
        if let subURL = proto.providerConfiguration?["subscriptionUrl"] as? String {
            config["subscriptionUrl"] = subURL
        }
        if let edge = proto.providerConfiguration?["edgeIPv4"] as? String {
            config["edgeIPv4"] = edge
        }

        return config
    }

    /// Edge /32 excluded from the tunnel — same as ProtectHostRoute on Win/mac.
    private func edgeIPv4() -> String? {
        if let ip = tunnelConfig["edgeIPv4"] as? String, !ip.isEmpty {
            return ip
        }
        let addr = (tunnelConfig["serverAddress"] as? String) ?? ""
        let host = addr.split(separator: ":").first.map(String.init) ?? addr
        let parts = host.split(separator: ".")
        if parts.count == 4, parts.allSatisfy({ UInt8($0) != nil }) {
            return host
        }
        return nil
    }

    /// 构建网络设置
    private func buildNetworkSettings() -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")

        // IPv4 设置：将默认路由指向隧道
        let ipv4 = NEIPv4Settings(addresses: ["10.88.0.2"], subnetMasks: ["255.255.255.0"])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        if let edge = edgeIPv4() {
            ipv4.excludedRoutes = [
                NEIPv4Route(destinationAddress: edge, subnetMask: "255.255.255.255")
            ]
        }
        settings.ipv4Settings = ipv4

        // IPv6 设置（可选）
        let ipv6 = NEIPv6Settings(addresses: ["fd00:aero::2"], networkPrefixLengths: [64])
        ipv6.includedRoutes = [NEIPv6Route.default()]
        settings.ipv6Settings = ipv6

        // DNS 设置
        let dns = NEDNSSettings(servers: ["223.5.5.5", "8.8.8.8"])
        settings.dnsSettings = dns

        // MTU
        settings.mtu = NSNumber(value: 1420)

        return settings
    }

    private func startPathMonitor() {
        pathMonitor?.cancel()
        let mon = NWPathMonitor()
        pathMonitor = mon
        mon.pathUpdateHandler = { [weak self] path in
            guard let self = self else { return }
            let key = path.availableInterfaces.map(\.name).joined(separator: ",") + "|\(path.status)"
            guard key != self.lastPathKey else { return }
            self.lastPathKey = key
            guard path.status == .satisfied else { return }
            self.applyTunnelSettings()
        }
        mon.start(queue: DispatchQueue.global(qos: .utility))
    }

    private func applyTunnelSettings() {
        if applyingSettings { return }
        applyingSettings = true
        let settings = buildNetworkSettings()
        setTunnelNetworkSettings(settings) { [weak self] err in
            self?.applyingSettings = false
            if let err = err {
                NSLog("[AERO] update tunnel settings: \(err)")
            }
        }
    }

    // MARK: - 用户偏好

    /// 加载用户在 App UI 中的设置
    private func loadUserPreferences() {
        let prefs = UserDefaults(suiteName: "group.aero.vpn")
        selectedCategories = prefs?.stringArray(forKey: "selected_categories") ?? []
        excludedBundleIDs = prefs?.stringArray(forKey: "excluded_bundle_ids") ?? []

        // 将分类解析为 Bundle ID 列表
        let bundleMap: [String: [String]] = [
            "banking": ["com.icbc.iphoneclient", "com.ccb.ccbplanner", "com.alipay.iphoneclient", "com.tenpay.weixin"],
            "gaming": ["com.tencent.smoba", "com.miHoYo.GenshinImpact"],
            "social": ["com.tencent.xin", "com.tencent.mqq", "com.laiwang.DingTalk"],
            "video": ["com.ss.iphone.ugc.Aweme", "tv.danmaku.bilianime"]
        ]

        for category in selectedCategories {
            if let ids = bundleMap[category] {
                excludedBundleIDs.append(contentsOf: ids)
            }
        }

        // 去重
        excludedBundleIDs = Array(Set(excludedBundleIDs))
    }

    /// 从 App Group 共享存储读取 Token
    private func readTokenFromSharedDefaults() -> String? {
        let prefs = UserDefaults(suiteName: "group.aero.vpn")
        return prefs?.string(forKey: "aero_token")
    }
}
