import SwiftUI

@main
struct ILLUMYXAPPApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

struct ContentView: View {
    var body: some View {
        NavigationStack {
            VStack(spacing: 20) {
                Image(systemName: "shield.lefthalf.filled")
                    .font(.system(size: 64))
                Text("ILLUMYXAPP")
                    .font(.largeTitle.bold())
                Text("Neon Guard protected app shell")
                    .foregroundStyle(.secondary)
            }
            .padding()
            .navigationTitle("ILLUMYXAPP")
        }
    }
}
