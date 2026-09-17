// Copyright 2025 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

// AeroBridge.swift
// Swift 调用 Go CGO 导出函数的桥接层。
//
// 使用方式：
//   1. 用 gomobile bind 或 go build -buildmode=c-archive 生成 iOS framework
//   2. 将 framework 导入 Xcode 项目
//   3. 调用 AeroBridge.shared.startTunnel(config:)

import Foundation
import NetworkExtension

/// AeroBridge 单例，封装所有 Go 函数调用
public class AeroBridge {
    public static let shared = AeroBridge()

    public typealias PacketCallback = (Data) -> Void
    private var packetCallback: PacketCallback?

    private init() {}

    /// 注册从 Go/gVisor 接收到的下行响应包回调（写回系统网卡）
    public func registerPacketCallback(_ callback: @escaping PacketCallback) {
        self.packetCallback = callback
        AeroTunnelRegisterPacketCallback { ptr, len in
            guard let ptr = ptr, len > 0 else { return }
            let data = Data(bytes: ptr, count: Int(len))
            AeroBridge.shared.packetCallback?(data)
        }
    }

    /// 启动 AERO 隧道
    /// - Parameter config: 隧道配置（ServerAddress, Token, SNI 等）
    /// - Returns: 启动结果
    @discardableResult
    public func startTunnel(config: [String: Any]) -> Result<Void, Error> {
        guard let jsonData = try? JSONSerialization.data(withJSONObject: config),
              let jsonString = String(data: jsonData, encoding: .utf8) else {
            return .failure(AeroError.invalidConfig)
        }

        let result = jsonString.withCString { cstr in
            // 调用 Go 导出函数 AeroTunnelStart
            guard let resultPtr = AeroTunnelStart(cstr) else {
                return "{\"error\":\"null result\"}"
            }
            let result = String(cString: resultPtr)
            FreeCString(resultPtr)
            return result
        }

        if let data = result.data(using: .utf8),
           let resp = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let error = resp["error"] as? String {
            return .failure(AeroError.goError(error))
        }

        return .success(())
    }

    /// 停止 AERO 隧道
    public func stopTunnel() {
        AeroTunnelStop()
    }

    /// 处理系统转发的 IP 包
    /// - Parameter packet: IP 包数据
    public func handlePacket(_ packet: Data) {
        packet.withUnsafeBytes { rawBuffer in
            guard let baseAddress = rawBuffer.baseAddress else { return }
            AeroTunnelHandlePacket(
                baseAddress.assumingMemoryBound(to: Int8.self),
                Int32(packet.count)
            )
        }
    }

    /// 获取隧道统计
    /// - Returns: 统计信息字典
    public func stats() -> [String: Any] {
        guard let resultPtr = AeroTunnelStats() else {
            return [:]
        }
        let result = String(cString: resultPtr)
        FreeCString(resultPtr)

        guard let data = result.data(using: .utf8),
              let dict = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return [:]
        }
        return dict
    }

    /// 更新分流规则
    /// - Parameter rules: 规则数组（域名、Bundle ID 等）
    @discardableResult
    public func updateRules(rules: [[String: Any]]) -> Result<Void, Error> {
        guard let jsonData = try? JSONSerialization.data(withJSONObject: rules),
              let jsonString = String(data: jsonData, encoding: .utf8) else {
            return .failure(AeroError.invalidConfig)
        }

        let result = jsonString.withCString { cstr in
            guard let resultPtr = AeroTunnelUpdateRules(cstr) else {
                return "{\"error\":\"null result\"}"
            }
            let result = String(cString: resultPtr)
            FreeCString(resultPtr)
            return result
        }

        if let data = result.data(using: .utf8),
           let resp = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let error = resp["error"] as? String {
            return .failure(AeroError.goError(error))
        }

        return .success(())
    }

    // MARK: - 错误类型

    public enum AeroError: LocalizedError {
        case invalidConfig
        case goError(String)
        case tunnelNotRunning

        public var errorDescription: String? {
            switch self {
            case .invalidConfig:
                return "Invalid tunnel configuration"
            case .goError(let msg):
                return "Go error: \(msg)"
            case .tunnelNotRunning:
                return "Tunnel is not running"
            }
        }
    }
}

// MARK: - Go 导出函数声明（由 Go framework 头文件提供）

public typealias PacketOutFunction = @convention(c) (UnsafePointer<Int8>?, Int32) -> Void

@_silgen_name("AeroTunnelRegisterPacketCallback")
func AeroTunnelRegisterPacketCallback(_ callback: PacketOutFunction)

@_silgen_name("AeroTunnelStart")
func AeroTunnelStart(_ configJSON: UnsafePointer<Int8>) -> UnsafeMutablePointer<Int8>?

@_silgen_name("AeroTunnelStop")
func AeroTunnelStop()

@_silgen_name("AeroTunnelHandlePacket")
func AeroTunnelHandlePacket(_ packet: UnsafePointer<Int8>, _ length: Int32)

@_silgen_name("AeroTunnelStats")
func AeroTunnelStats() -> UnsafeMutablePointer<Int8>?

@_silgen_name("AeroTunnelUpdateRules")
func AeroTunnelUpdateRules(_ rulesJSON: UnsafePointer<Int8>) -> UnsafeMutablePointer<Int8>?

@_silgen_name("FreeCString")
func FreeCString(_ s: UnsafeMutablePointer<Int8>)
