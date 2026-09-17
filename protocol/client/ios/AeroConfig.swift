// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// AeroConfig.swift
// iOS App 配置数据模型和分流规则定义。

import Foundation

// MARK: - 分流分类

public enum SplitCategory: String, CaseIterable, Identifiable {
    case banking = "banking"
    case gaming = "gaming"
    case social = "social"
    case video = "video"

    public var id: String { rawValue }

    public var displayName: String {
        switch self {
        case .banking: return "银行金融"
        case .gaming: return "游戏娱乐"
        case .social: return "社交办公"
        case .video: return "视频直播"
        }
    }

    public var icon: String {
        switch self {
        case .banking: return "dollarsign.circle"
        case .gaming: return "gamecontroller"
        case .social: return "message"
        case .video: return "play.rectangle"
        }
    }

    /// 该分类下预置的 App 列表
    public var presetApps: [DirectApp] {
        switch self {
        case .banking:
            return [
                DirectApp(name: "工商银行", bundleID: "com.icbc.iphoneclient", category: .banking),
                DirectApp(name: "建设银行", bundleID: "com.ccb.ccbplanner", category: .banking),
                DirectApp(name: "支付宝", bundleID: "com.alipay.iphoneclient", category: .banking),
                DirectApp(name: "微信支付", bundleID: "com.tenpay.weixin", category: .banking),
            ]
        case .gaming:
            return [
                DirectApp(name: "王者荣耀", bundleID: "com.tencent.smoba", category: .gaming),
                DirectApp(name: "原神", bundleID: "com.miHoYo.GenshinImpact", category: .gaming),
            ]
        case .social:
            return [
                DirectApp(name: "微信", bundleID: "com.tencent.xin", category: .social),
                DirectApp(name: "QQ", bundleID: "com.tencent.mqq", category: .social),
                DirectApp(name: "钉钉", bundleID: "com.laiwang.DingTalk", category: .social),
            ]
        case .video:
            return [
                DirectApp(name: "抖音", bundleID: "com.ss.iphone.ugc.Aweme", category: .video),
                DirectApp(name: "Bilibili", bundleID: "tv.danmaku.bilianime", category: .video),
            ]
        }
    }
}

// MARK: - 直连 App 模型

public struct DirectApp: Codable, Identifiable {
    public let id = UUID()
    public let name: String
    public let bundleID: String
    public let category: SplitCategory

    enum CodingKeys: String, CodingKey {
        case name, bundleID, category
    }
}

// MARK: - 订阅配置

public struct AeroSubscription: Codable {
    public let version: String
    public let servers: [AeroServer]
    public let createdAt: Int64

    public struct AeroServer: Codable {
        public let name: String
        public let address: String
        public let token: String
        public let sni: String
        public let protocol: String
    }
}

// MARK: - 隧道运行时配置

public struct AeroTunnelConfig {
    public var serverAddress: String
    public var token: String
    public var sni: String
    public var fingerprint: String
    public var splitEnabled: Bool
    public var mtu: Int
    public var dns: [String]
    /// Edge IPv4 excluded from the tunnel (ProtectHostRoute on Win/mac).
    public var edgeIPv4: String

    public static let `default` = AeroTunnelConfig(
        serverAddress: "",
        token: "",
        sni: "cdn-aero.com",
        fingerprint: "chrome",
        splitEnabled: true,
        mtu: 1420,
        dns: ["223.5.5.5", "8.8.8.8"],
        edgeIPv4: ""
    )
}
