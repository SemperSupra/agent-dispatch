import UIKit

// Original R50 synthetic-only app. No network, accounts, permissions, device
// enrollment or access to phone identifiers. Shared preferences serve ONLY
// as an independent verifier-visible sandbox launch marker.
@main
final class AppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?

    func application(_ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions:
        [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        let view = UIViewController()
        view.view.backgroundColor = UIColor.white
        let label = UILabel()
        label.text = "R50_COMPANION_READY"
        label.font = UIFont.systemFont(ofSize: 21)
        label.textAlignment = .center
        label.translatesAutoresizingMaskIntoConstraints = false
        view.view.addSubview(label)
        NSLayoutConstraint.activate([
            label.centerXAnchor.constraint(equalTo: view.view.centerXAnchor),
            label.centerYAnchor.constraint(equalTo: view.view.centerYAnchor)
        ])
        let newWindow = UIWindow(frame: UIScreen.main.bounds)
        newWindow.rootViewController = view
        newWindow.makeKeyAndVisible()
        window = newWindow
        UserDefaults.standard.set("R50_IOS_APP_LAUNCHED", forKey: "r50.status")
        return UserDefaults.standard.synchronize()
    }
}
