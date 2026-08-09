import SwiftUI

@main
struct TamisApp: App {
    @State private var state = AppState()
    @State private var lists = FilterListsModel.makeDefault()
    @State private var engines: EngineModel

    init() {
        let lists = FilterListsModel.makeDefault()
        let engines = EngineModel(manager: lists.manager)
        lists.onListsChanged = { [engines] in engines.rebuild() }
        _lists = State(initialValue: lists)
        _engines = State(initialValue: engines)
    }

    var body: some Scene {
        Window("Tamis", id: "main") {
            MainWindow()
                .environment(state)
                .environment(lists)
                .environment(engines)
                // Wide enough that the sidebar and a table can coexist without either
                // being useless.
                .frame(minWidth: 900, minHeight: 600)
        }
        .defaultSize(width: 1000, height: 680)
        .commands {
            // Closing the window must not quit: Tamis keeps filtering, and the menu bar
            // is where it lives.
            CommandGroup(replacing: .newItem) {}
        }

        MenuBarExtra {
            MenuBarPanel()
                .environment(state)
                .environment(lists)
                .environment(engines)
        } label: {
            Image(systemName: state.protection.symbolName)
        }
        .menuBarExtraStyle(.window)
    }
}

extension AppState.Protection {
    /// State is read from the shape, never from colour. A coloured dot at 16 points is
    /// unreadable and against every macOS convention.
    var symbolName: String {
        switch self {
        case .active:         "circle.grid.3x3.fill"
        case .paused:         "circle.grid.3x3"
        case .notConfigured:  "circle.grid.3x3.circle"
        }
    }

    var label: String {
        switch self {
        case .active:        "Active"
        case .paused:        "En pause"
        case .notConfigured: "Non configuré"
        }
    }
}
