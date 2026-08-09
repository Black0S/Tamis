import Foundation
import Testing
@testable import TamisLists

@Suite("Catalogue")
struct CatalogTests {

    private let catalog = FilterListCatalog.bundled

    @Test("The shipped catalogue decodes and is not empty")
    func decodes() {
        #expect(catalog.entries.count > 150)
        #expect(!catalog.generatedAt.isEmpty)
    }

    /// The size that makes the founding rule workable — browsable offline, and small
    /// enough that embedding it is not a cost worth arguing about.
    @Test("The catalogue stays metadata-sized")
    func size() throws {
        let url = try #require(
            Bundle.module.url(forResource: "catalog", withExtension: "json", subdirectory: "Resources")
                ?? Bundle.module.url(forResource: "catalog", withExtension: "json")
        )
        let bytes = try Data(contentsOf: url).count
        #expect(bytes < 200_000, "\(bytes) bytes — metadata only, no rules")
    }

    @Test("Identifiers and download URLs are unique")
    func unique() {
        #expect(Set(catalog.entries.map(\.id)).count == catalog.entries.count)
        #expect(Set(catalog.entries.map(\.downloadURL)).count == catalog.entries.count)
    }

    @Test("Every entry has a name and an https download URL")
    func wellFormed() {
        for entry in catalog.entries {
            #expect(!entry.name.isEmpty, "\(entry.id) has no name")
            #expect(entry.downloadURL.scheme == "https", "\(entry.id): \(entry.downloadURL)")
        }
    }

    @Test("Both registries and the DNS section are present")
    func registries() {
        let registries = Set(catalog.entries.map(\.registry))
        #expect(registries == ["uBlock Origin", "AdGuard", "Tamis"])
        #expect(!catalog.entries(in: .dns).isEmpty)
    }

    /// A one-click set of 50 lists is not a suggestion, it is a decision taken for
    /// somebody. This pins the size as much as the contents.
    @Test("The suggested selection is small and covers both layers")
    func suggestedSelection() {
        let suggested = catalog.suggestedSelection
        #expect(suggested.count >= 8 && suggested.count <= 15, "\(suggested.count) lists")
        #expect(suggested.contains { $0.category == .dns }, "the resolver would start empty")
        #expect(suggested.contains { $0.name.contains("EasyList") })
    }

    @Test("Nothing is enabled by having been catalogued")
    func nothingEnabled() {
        // There is no `enabled` anywhere in the catalogue: it describes what exists,
        // never what is on. Enabling is the user's act and is stored elsewhere.
        #expect(catalog.suggestedSelection.count < catalog.entries.count)
    }

    @Test("Language filters can be offered without being applied")
    func byLanguage() {
        let french = catalog.entries(forLanguages: ["fr-FR"])
        #expect(!french.isEmpty)
        #expect(french.allSatisfy { !$0.inSuggestedSelection })
    }

    @Test("Search covers name, description and registry")
    func search() {
        #expect(catalog.search("easyprivacy").contains { $0.name.contains("EasyPrivacy") })
        #expect(catalog.search("AdGuard").count > 10)
        #expect(catalog.search("").count == catalog.entries.count)
        #expect(catalog.search("zzzzz").isEmpty)
    }

    @Test("Categories are populated and ordered for display")
    func categories() {
        let populated = catalog.populatedCategories
        #expect(populated.first == .base)
        #expect(populated.contains(.regional))
        #expect(catalog.entries(in: .regional).count > 50)
    }

    /// Deprecated lists stay listed. Removing them would silently drop a subscription
    /// somebody still has; saying so lets them decide.
    @Test("Deprecated lists are kept and marked")
    func deprecated() {
        #expect(catalog.entries.contains { $0.deprecated })
        #expect(catalog.entries.filter(\.deprecated).allSatisfy { !$0.inSuggestedSelection })
    }
}
