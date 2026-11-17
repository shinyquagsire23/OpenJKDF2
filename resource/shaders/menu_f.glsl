uniform sampler2D tex;
uniform sampler2D worldPalette;
uniform sampler2D displayPalette;

// Added: PNG menu background support
uniform sampler2D pngMenuBackground;
uniform sampler2D pngMenuMask;
uniform int usePngMenuBackground;
uniform vec2 pngMenuUvScale;

// Added: PNG menu background support
uniform int pngMenuFullscreen;
uniform vec2 pngMenuCropScale;
// Added: PNG menu background support - multiplayer character compositing.
uniform int pngMenuCharacterPreview;

in vec4 f_color;
in vec2 f_uv;
out vec4 fragColor;

void main(void)
{
    // Added: PNG menu background support
    // Draw a fullscreen PNG with centered, height-based cropping.
    if (pngMenuFullscreen != 0)
    {
        vec2 pngUv = vec2(
            0.5 + (f_uv.x - 0.5) * pngMenuCropScale.x,
            0.5 + (f_uv.y - 0.5) * pngMenuCropScale.y
        );

        fragColor = texture(pngMenuBackground, pngUv);
        return;
    }

    // Added: PNG menu background support - draw the RGBA character preview.
    if (pngMenuCharacterPreview != 0)
    {
        fragColor = texture(tex, vec2(f_uv.x, 1.0 - f_uv.y));
        return;
    }
    vec4 sampled = texture(tex, f_uv);
    float index = sampled.r;

    vec4 palvald = texture(displayPalette, vec2(index, 0.5));

    // Added: PNG menu background support
    if (usePngMenuBackground != 0)
    {
        // The original menu buffer may be larger than 640x480.
        // Convert its texture coordinates to the 640x480 GUI area.
        vec2 guiUv = f_uv * pngMenuUvScale;

        // Added: PNG menu background support
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
