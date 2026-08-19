import Foundation

public enum AccessDecision: String, Codable, Sendable {
    case allow = "ALLOW"
    case deny = "DENY"
}

public struct AccessRequest: Codable, Sendable {
    public let credential: String

    public init(credential: String) {
        self.credential = credential
    }
}

public struct AccessResponse: Codable, Sendable {
    public let decision: AccessDecision
}

public enum NeonGuardClientError: Error {
    case invalidResponse
    case denied
}

/// iOS client boundary for a server-authorized Neon Guard decision.
/// No blocklist, HMAC secret, or authorization policy is stored in the app.
public actor NeonGuardClient {
    private let endpoint: URL
    private let session: URLSession

    public init(endpoint: URL, session: URLSession = .shared) {
        self.endpoint = endpoint
        self.session = session
    }

    public func evaluate(credential: String) async throws -> AccessDecision {
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.httpBody = try JSONEncoder().encode(AccessRequest(credential: credential))

        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse,
              (200...299).contains(http.statusCode) else {
            throw NeonGuardClientError.invalidResponse
        }

        let result = try JSONDecoder().decode(AccessResponse.self, from: data)
        if result.decision == .deny {
            throw NeonGuardClientError.denied
        }
        return result.decision
    }
}
