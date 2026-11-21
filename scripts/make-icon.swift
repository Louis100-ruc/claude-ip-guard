import AppKit

guard CommandLine.arguments.count >= 2 else {
    fputs("Usage: make-icon.swift <output-png-path>\n", stderr)
    exit(1)
}
let outPath = CommandLine.arguments[1]
let size = NSSize(width: 1024, height: 1024)

guard let bitmap = NSBitmapImageRep(
    bitmapDataPlanes: nil,
    pixelsWide: Int(size.width),
    pixelsHigh: Int(size.height),
    bitsPerSample: 8,
    samplesPerPixel: 4,
    hasAlpha: true,
    isPlanar: false,
    colorSpaceName: .deviceRGB,
    bytesPerRow: 0,
    bitsPerPixel: 0
) else { exit(1) }

NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: bitmap)

let rect = NSRect(origin: .zero, size: size)
let insetRect = rect.insetBy(dx: 72, dy: 72)
let squircle = NSBezierPath(roundedRect: insetRect, xRadius: 210, yRadius: 210)

let gradient = NSGradient(colors: [
    NSColor(calibratedRed: 0.06, green: 0.14, blue: 0.18, alpha: 1.0),
    NSColor(calibratedRed: 0.04, green: 0.30, blue: 0.24, alpha: 1.0),
    NSColor(calibratedRed: 0.10, green: 0.62, blue: 0.42, alpha: 1.0)
])!
gradient.draw(in: squircle, angle: 125)

NSColor.white.withAlphaComponent(0.18).setStroke()
squircle.lineWidth = 10
squircle.stroke()

// Subtle radar rings
let center = NSPoint(x: 512, y: 512)
for radius in [CGFloat(290), CGFloat(210)] {
    let ring = NSBezierPath(ovalIn: NSRect(x: center.x - radius, y: center.y - radius, width: radius * 2, height: radius * 2))
    NSColor.white.withAlphaComponent(0.12).setStroke()
    ring.lineWidth = 8
    ring.stroke()
}

// Shield silhouette
let shield = NSBezierPath()
shield.move(to: NSPoint(x: 512, y: 775))
shield.curve(to: NSPoint(x: 735, y: 690), controlPoint1: NSPoint(x: 590, y: 745), controlPoint2: NSPoint(x: 675, y: 710))
shield.line(to: NSPoint(x: 735, y: 500))
shield.curve(to: NSPoint(x: 512, y: 235), controlPoint1: NSPoint(x: 735, y: 365), controlPoint2: NSPoint(x: 620, y: 275))
shield.curve(to: NSPoint(x: 289, y: 500), controlPoint1: NSPoint(x: 404, y: 275), controlPoint2: NSPoint(x: 289, y: 365))
shield.line(to: NSPoint(x: 289, y: 690))
shield.curve(to: NSPoint(x: 512, y: 775), controlPoint1: NSPoint(x: 349, y: 710), controlPoint2: NSPoint(x: 434, y: 745))
shield.close()

NSColor.white.withAlphaComponent(0.95).setFill()
shield.fill()

// Checkmark inside shield
let check = NSBezierPath()
check.move(to: NSPoint(x: 405, y: 515))
check.line(to: NSPoint(x: 482, y: 438))
check.line(to: NSPoint(x: 632, y: 592))
check.lineWidth = 46
check.lineCapStyle = .round
check.lineJoinStyle = .round
NSColor(calibratedRed: 0.08, green: 0.56, blue: 0.36, alpha: 1.0).setStroke()
check.stroke()

NSGraphicsContext.restoreGraphicsState()

if let pngData = bitmap.representation(using: .png, properties: [:]) {
    try pngData.write(to: URL(fileURLWithPath: outPath))
}
