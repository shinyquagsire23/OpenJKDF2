uniform sampler2D tex;
uniform sampler2D worldPalette;
uniform sampler2D displayPalette;

// PNG menu background support
uniform sampler2D pngMenuBackground;
uniform sampler2D pngMenuMask;
uniform int usePngMenuBackground;
uniform vec2 pngMenuUvScale;
uniform int pngMenuFullscreen;
uniform vec2 pngMenuCropScale;
// PNG menu background support - multiplayer character compositing.
uniform int pngMenuCharacterPreview;

in vec4 f_color;
in vec2 f_uv;
out vec4 fragColor;

void main(void)
{
    // Draw a fullscreen PNG with centered, height-based cropping.
    if (pngMenuFullscreen != 0)
    {
        vec2 pngUv = vec2(
            0.5 + (f_uv.x - 0.5) * pngMenuCropScale.x,
            0.5 + (f_uv.y - 0.5) * pngMenuCropScale.y
        );

        // Added: PNG menu background support
        // Display black borders instead of stretching the PNG's edge pixels.
        if (pngUv.x < 0.0 || pngUv.x > 1.0 ||
            pngUv.y < 0.0 || pngUv.y > 1.0)
        {
            fragColor = vec4(0.0, 0.0, 0.0, 1.0);
        }
        else
        {
            fragColor = texture(pngMenuBackground, pngUv);
        }
        return;
    }

    if (pngMenuCharacterPreview != 0)
    {
        fragColor = texture(tex, vec2(f_uv.x, 1.0 - f_uv.y));
        return;
    }
    vec4 sampled = texture(tex, f_uv);
    float index = sampled.r;

    vec4 palvald = texture(displayPalette, vec2(index, 0.5));

    if (usePngMenuBackground != 0)
    {
        // The original menu buffer may be larger than 640x480.
        // Convert its texture coordinates to the 640x480 GUI area.
        vec2 guiUv = f_uv * pngMenuUvScale;

        // The fullscreen PNG is already drawn behind the original GUI.
        float mask = texture(pngMenuMask, guiUv).r;

        vec4 guiColor = vec4(palvald.rgb, 1.0) * f_color;

        // Preserve GUI pixels while allowing the fullscreen PNG to show through.
        fragColor = vec4(guiColor.rgb, guiColor.a * mask);
        return;
    }

    // Original menu rendering behavior.
    if (index == 0.0)
        discard;

    fragColor = vec4(palvald.rgb, 1.0) * f_color;
}
