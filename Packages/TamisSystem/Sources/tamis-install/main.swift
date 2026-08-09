import Foundation
import TamisSystem

// What installing would change, and what is already in place.
//
//   swift run --package-path Packages/TamisSystem tamis-install
//
// This reads and prints. It installs nothing: every change below is applied by the
// application, after the user has seen this list and agreed to it.

setvbuf(stdout, nil, _IOLBF, 0)

let plan = Installation.plan()

print("Ce qu'installer Tamis changerait\n")
for change in plan {
    let state = change.isApplied ? "déjà en place" : "à faire"
    let scope = change.scope == .administrator ? "mot de passe requis" : "sans privilège"
    print("  \(change.title)   [\(state) · \(scope)]")
    print("      \(change.effect)")
    for path in change.paths {
        print("      fichier  \(path.path(percentEncoded: false))")
    }
    print("      annuler  \(change.undoCommand)")
    print("")
}

let applied = plan.filter(\.isApplied)
print(applied.isEmpty
      ? "  Rien n'est installé sur ce Mac."
      : "  \(applied.count) changement(s) déjà en place.")

let data = Installation.userData()
if !data.isEmpty {
    print("\n  Données existantes — ce sont les vôtres, la désinstallation les propose")
    print("  séparément plutôt que de les emporter avec le logiciel :")
    for url in data { print("      \(url.path(percentEncoded: false))") }
}
