"""
Generate Sentinel application icon.

Creates a professional-looking icon for the Sentinel Network Assistant.
"""
from PIL import Image, ImageDraw, ImageFont
import os


def create_sentinel_icon():
    """Create a Sentinel icon with shield motif."""
    sizes = [16, 32, 48, 64, 128, 256]
    images = []

    for size in sizes:
        # Create image with transparent background
        img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)

        # Colors - dark blue/teal theme for security/network
        primary_color = (20, 80, 120, 255)      # Deep blue
        accent_color = (0, 180, 200, 255)       # Cyan/teal
        highlight_color = (100, 200, 220, 255)  # Light cyan

        # Calculate proportional dimensions
        margin = size // 10
        shield_width = size - 2 * margin
        shield_height = int(shield_width * 1.15)

        # Shield path coordinates (centered)
        cx = size // 2
        top = margin
        bottom = top + shield_height
        left = margin
        right = size - margin
        mid_y = top + shield_height // 2

        # Draw shield shape
        shield_points = [
            (cx, top),                    # Top center
            (right, top + size // 8),     # Top right
            (right, mid_y),               # Mid right
            (cx, bottom),                 # Bottom point
            (left, mid_y),                # Mid left
            (left, top + size // 8),      # Top left
        ]

        # Draw filled shield
        draw.polygon(shield_points, fill=primary_color, outline=accent_color)

        # Draw inner accent (network node pattern)
        inner_margin = size // 5
        inner_cx = cx
        inner_cy = top + shield_height // 2 - size // 10

        # Central node
        node_radius = max(2, size // 12)
        draw.ellipse(
            [inner_cx - node_radius, inner_cy - node_radius,
             inner_cx + node_radius, inner_cy + node_radius],
            fill=accent_color
        )

        # Surrounding nodes (network pattern)
        if size >= 32:
            offset = size // 4
            node_positions = [
                (inner_cx - offset, inner_cy - offset // 2),
                (inner_cx + offset, inner_cy - offset // 2),
                (inner_cx - offset // 2, inner_cy + offset),
                (inner_cx + offset // 2, inner_cy + offset),
            ]

            small_radius = max(1, size // 16)

            # Draw connecting lines first
            for nx, ny in node_positions:
                draw.line(
                    [(inner_cx, inner_cy), (nx, ny)],
                    fill=highlight_color,
                    width=max(1, size // 32)
                )

            # Draw outer nodes
            for nx, ny in node_positions:
                draw.ellipse(
                    [nx - small_radius, ny - small_radius,
                     nx + small_radius, ny + small_radius],
                    fill=accent_color
                )

        images.append(img)

    return images


def main():
    """Generate and save the icon."""
    # Ensure output directory exists
    output_dir = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        'src', 'sentinel', 'assets'
    )
    os.makedirs(output_dir, exist_ok=True)

    icon_path = os.path.join(output_dir, 'sentinel.ico')

    # Generate icon images
    images = create_sentinel_icon()

    # Save as ICO (includes all sizes)
    images[0].save(
        icon_path,
        format='ICO',
        sizes=[(img.size[0], img.size[1]) for img in images],
        append_images=images[1:]
    )

    print(f"Icon saved to: {icon_path}")

    # Also save a PNG for other uses
    png_path = os.path.join(output_dir, 'sentinel.png')
    images[-1].save(png_path, format='PNG')
    print(f"PNG saved to: {png_path}")


if __name__ == "__main__":
    main()
