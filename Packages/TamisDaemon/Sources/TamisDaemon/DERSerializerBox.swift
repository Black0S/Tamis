import Foundation
import SwiftASN1
import X509

/// Turns a certificate into the bytes a TLS library expects.
struct DERSerializerBox {
    mutating func der(of certificate: Certificate) throws -> [UInt8] {
        var serializer = DER.Serializer()
        try serializer.serialize(certificate)
        return serializer.serializedBytes
    }
}
