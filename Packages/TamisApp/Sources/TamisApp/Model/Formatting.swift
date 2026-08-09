import Foundation

enum Formatting {
    /// Byte counts as shown in the interface.
    ///
    /// `spellsOutZero` is off deliberately: the default renders 0 as "Zéro ko", which in
    /// a column of digits reads as a different kind of value rather than as the smallest
    /// one. Counters should stay comparable at a glance.
    static func bytes(_ count: Int) -> String {
        Int64(count).formatted(.byteCount(style: .file, spellsOutZero: false))
    }
}
