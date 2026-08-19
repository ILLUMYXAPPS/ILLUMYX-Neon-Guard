import Foundation
import Security

public protocol TrustedDeviceStore: Sendable {
    func save(token: String) throws
    func load() throws -> String?
    func clear() throws
}

public enum TrustedDeviceStoreError: Error {
    case invalidToken
    case keychainFailure(OSStatus)
}

/// Stores only a server-issued opaque trusted-device token in the iOS Keychain.
/// The client does not derive trust from device identifiers or store authorization policy.
public struct KeychainTrustedDeviceStore: TrustedDeviceStore, Sendable {
    private let service: String
    private let account: String

    public init(service: String = "com.illumyx.neonguard", account: String = "trusted-device-token") {
        self.service = service
        self.account = account
    }

    public func save(token: String) throws {
        guard !token.isEmpty else { throw TrustedDeviceStoreError.invalidToken }
        let data = Data(token.utf8)
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account
        ]
        let attributes: [CFString: Any] = [kSecValueData: data, kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly]
        let updateStatus = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if updateStatus == errSecItemNotFound {
            var item = query
            attributes.forEach { item[$0.key] = $0.value }
            let status = SecItemAdd(item as CFDictionary, nil)
            guard status == errSecSuccess else { throw TrustedDeviceStoreError.keychainFailure(status) }
        } else if updateStatus != errSecSuccess {
            throw TrustedDeviceStoreError.keychainFailure(updateStatus)
        }
    }

    public func load() throws -> String? {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw TrustedDeviceStoreError.keychainFailure(status) }
        guard let data = result as? Data else { throw TrustedDeviceStoreError.invalidToken }
        return String(data: data, encoding: .utf8)
    }

    public func clear() throws {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw TrustedDeviceStoreError.keychainFailure(status)
        }
    }
}
