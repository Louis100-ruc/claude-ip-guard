import AppKit
import SwiftUI

@MainActor
private final class FixedCardViewController: NSViewController {
    private let rootView: StatusCardView
    private let fixedSize: NSSize

    init(rootView: StatusCardView, size: NSSize) {
        self.rootView = rootView
        self.fixedSize = size
        super.init(nibName: nil, bundle: nil)
        self.preferredContentSize = size
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override func loadView() {
        let container = NSView(frame: NSRect(origin: .zero, size: fixedSize))
        container.autoresizingMask = [.width, .height]

        let hostingView = NSHostingView(rootView: rootView)
        hostingView.translatesAutoresizingMaskIntoConstraints = false
        hostingView.sizingOptions = []
        container.addSubview(hostingView)

        NSLayoutConstraint.activate([
            hostingView.leadingAnchor.constraint(equalTo: container.leadingAnchor),
            hostingView.trailingAnchor.constraint(equalTo: container.trailingAnchor),
            hostingView.topAnchor.constraint(equalTo: container.topAnchor),
            hostingView.bottomAnchor.constraint(equalTo: container.bottomAnchor)
        ])

        self.view = container
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate, NSPopoverDelegate {
    private let store = MonitorStore()
    private var statusItem: NSStatusItem?
    private var popover: NSPopover?
    private var floatingPanel: NSPanel?

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)

        setupStatusItem()
        setupPopover()

        store.onSnapshotUpdated = { [weak self] _, _ in
            self?.updateStatusItemAppearance()
        }
        store.onToggleFloating = { [weak self] in
            self?.toggleFloatingWindow()
        }
        store.onFloatingStyleChanged = { [weak self] in
            self?.applyFloatingLevel()
        }

        store.start()
        updateStatusItemAppearance()
    }

    func applicationWillTerminate(_ notification: Notification) {
        store.stop()
    }

    private func setupStatusItem() {
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = item.button {
            button.imagePosition = .imageLeading
            button.imageHugsTitle = true
            button.lineBreakMode = .byClipping
            if let cell = button.cell as? NSButtonCell {
                cell.truncatesLastVisibleLine = false
                cell.lineBreakMode = .byClipping
            }
            button.target = self
            button.action = #selector(handleStatusBarClick(_:))
            button.sendAction(on: [.leftMouseUp, .rightMouseUp])
        }
        self.statusItem = item
    }

    private let cardSize = NSSize(width: StatusCardView.cardWidth, height: StatusCardView.cardHeight)

    private func setupPopover() {
        self.popover = makePopover()
    }

    private func makePopover() -> NSPopover {
        let popover = NSPopover()
        popover.behavior = .transient
        popover.animates = true
        popover.delegate = self
        popover.contentSize = cardSize

        let vc = FixedCardViewController(
            rootView: StatusCardView(store: store, isFloatingWindow: false),
            size: cardSize
        )
        popover.contentViewController = vc
        return popover
    }

    private func makeStatusDotImage(color: NSColor) -> NSImage {
        let size = NSSize(width: 9, height: 9)
        let image = NSImage(size: size, flipped: false) { rect in
            let insetRect = rect.insetBy(dx: 0.75, dy: 0.75)
            let path = NSBezierPath(ovalIn: insetRect)
            color.setFill()
            path.fill()
            NSColor.black.withAlphaComponent(0.18).setStroke()
            path.lineWidth = 0.6
            path.stroke()
            return true
        }
        image.isTemplate = false
        return image
    }

    private func updateStatusItemAppearance() {
        applyStatusItemLayout()
        // Re-apply after next runloop turn in case an NSMenu/NSPopover transition locked bounds
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.08) { [weak self] in
            self?.applyStatusItemLayout()
        }
    }

    private func applyStatusItemLayout() {
        guard let item = statusItem, let button = item.button else { return }

        let text = " " + store.menuBarText()
        let font = NSFont.monospacedDigitSystemFont(ofSize: 12, weight: .medium)
        let paragraph = NSMutableParagraphStyle()
        paragraph.lineBreakMode = .byClipping

        let attrs: [NSAttributedString.Key: Any] = [
            .font: font,
            .paragraphStyle: paragraph
        ]
        let attrTitle = NSAttributedString(string: text, attributes: attrs)

        let measuredSize = attrTitle.size()
        let boundingWidth = attrTitle.boundingRect(
            with: NSSize(width: 600, height: 22),
            options: [.usesLineFragmentOrigin, .usesFontLeading]
        ).width
        let textWidth = ceil(max(measuredSize.width, boundingWidth))

        let dotWidth: CGFloat = 9
        let totalWidth = max(64, dotWidth + textWidth + 24)

        button.image = makeStatusDotImage(color: store.menuBarDotColor())
        button.imagePosition = .imageLeading
        button.attributedTitle = attrTitle
        button.lineBreakMode = .byClipping
        item.length = totalWidth
        button.invalidateIntrinsicContentSize()
        button.needsLayout = true
        button.needsDisplay = true
    }

    func popoverDidClose(_ notification: Notification) {
        applyStatusItemLayout()
    }

    @objc private func handleStatusBarClick(_ sender: NSStatusBarButton) {
        guard let event = NSApp.currentEvent else {
            togglePopover(sender)
            return
        }
        if event.type == .rightMouseUp {
            showContextMenu(for: sender)
        } else {
            togglePopover(sender)
        }
    }

    private func togglePopover(_ sender: NSStatusBarButton) {
        if let existing = popover, existing.isShown {
            existing.performClose(sender)
            return
        }
        let fresh = makePopover()
        self.popover = fresh
        fresh.show(relativeTo: sender.bounds, of: sender, preferredEdge: .minY)
        NSApp.activate(ignoringOtherApps: true)
    }

    private func showContextMenu(for button: NSStatusBarButton) {
        popover?.performClose(nil)
        let menu = NSMenu()
        menu.addItem(NSMenuItem(title: "立即重新检测", action: #selector(menuRefresh), keyEquivalent: "r"))
        let floatTitle = store.isFloatingVisible ? "隐藏桌面悬浮窗" : "显示桌面悬浮窗"
        menu.addItem(NSMenuItem(title: floatTitle, action: #selector(menuToggleFloating), keyEquivalent: "p"))
        let styleTitle = store.menuBarStyle == .compact ? "切换为完整显示（地区 + IP）" : "切换为简洁显示（地区 + DNS）"
        menu.addItem(NSMenuItem(title: styleTitle, action: #selector(menuToggleStyle), keyEquivalent: ""))
        menu.addItem(NSMenuItem(title: "复制本地 API 地址", action: #selector(menuCopyAPI), keyEquivalent: ""))
        menu.addItem(NSMenuItem.separator())
        menu.addItem(NSMenuItem(title: "退出 ClaudeIPGuard", action: #selector(menuQuit), keyEquivalent: "q"))
        menu.popUp(positioning: nil, at: NSPoint(x: 0, y: button.bounds.height + 4), in: button)
    }

    @objc private func menuRefresh() {
        store.triggerCheck(reason: "手动刷新")
    }

    @objc private func menuToggleFloating() {
        toggleFloatingWindow()
    }

    @objc private func menuToggleStyle() {
        store.menuBarStyle = (store.menuBarStyle == .compact) ? .withIP : .compact
    }

    @objc private func menuCopyAPI() {
        store.copyToClipboard("http://127.0.0.1:17899/api/status", label: "本地 API 地址")
    }

    @objc private func menuQuit() {
        NSApp.terminate(nil)
    }

    // MARK: - Floating Desktop HUD Window
    private func toggleFloatingWindow() {
        if let panel = floatingPanel, panel.isVisible {
            panel.orderOut(nil)
            store.isFloatingVisible = false
            return
        }
        popover?.performClose(nil)
        showFloatingWindow()
    }

    private func showFloatingWindow() {
        if floatingPanel == nil {
            let panel = NSPanel(
                contentRect: NSRect(origin: .zero, size: cardSize),
                styleMask: [.titled, .closable, .fullSizeContentView, .nonactivatingPanel],
                backing: .buffered,
                defer: false
            )
            panel.isFloatingPanel = true
            panel.hidesOnDeactivate = false
            panel.titleVisibility = .hidden
            panel.titlebarAppearsTransparent = true
            panel.isMovableByWindowBackground = true
            panel.backgroundColor = .clear
            panel.isOpaque = false
            panel.hasShadow = true
            panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
            panel.delegate = self

            let vc = FixedCardViewController(
                rootView: StatusCardView(store: store, isFloatingWindow: true),
                size: cardSize
            )
            vc.view.wantsLayer = true
            vc.view.layer?.cornerRadius = 14
            vc.view.layer?.masksToBounds = true
            panel.contentViewController = vc
            panel.setContentSize(cardSize)

            let restored = panel.setFrameAutosaveName("ClaudeIPGuardFloatingPanel")
            if !restored, let screen = NSScreen.main {
                let visible = screen.visibleFrame
                let size = panel.frame.size
                let origin = NSPoint(
                    x: visible.maxX - size.width - 18,
                    y: visible.maxY - size.height - 18
                )
                panel.setFrameOrigin(origin)
            }

            self.floatingPanel = panel
        }

        applyFloatingLevel()
        floatingPanel?.orderFrontRegardless()
        store.isFloatingVisible = true
    }

    private func applyFloatingLevel() {
        floatingPanel?.level = store.floatingAlwaysOnTop ? .floating : .normal
    }

    func windowWillClose(_ notification: Notification) {
        if (notification.object as? NSPanel) == floatingPanel {
            store.isFloatingVisible = false
        }
    }
}
