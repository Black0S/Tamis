import SwiftUI

@main
struct TamisApp: App {
    @State private var state = AppState()
    @State private var lists = FilterListsModel.makeDefault()
    @State private var engines: EngineModel
    @State private var resolver = ResolverModel()
    @State private var scripts = ScriptsModel.makeDefault()
    @State private var applications = ApplicationsModel()
    @State private var history = HistoryModel.makeDefault()
    @State private var alerts = AlertsModel()
    @State private var onboarding = OnboardingModel()

    init() {
        let lists = FilterListsModel.makeDefault()
        let engines = EngineModel(manager: lists.manager)
        lists.onListsChanged = { [engines] in engines.rebuild() }
        // The resolver writes what it decides; it works without a history, and the app
        // is what gives it one.
        let history = HistoryModel.makeDefault()
        let resolver = ResolverModel()
        resolver.history = history
        _history = State(initialValue: history)
        _resolver = State(initialValue: resolver)
        _lists = State(initialValue: lists)
        _engines = State(initialValue: engines)
    }

    var body: some Scene {
        Window("Tamis", id: "main") {
            MainWindow()
                .environment(state)
                .environment(lists)
                .environment(engines)
                .environment(resolver)
                .environment(scripts)
                .environment(applications)
                .environment(history)
                .environment(alerts)
                .environment(onboarding)
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
                .environment(resolver)
                .environment(history)
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
