uniform sampler2D tex;
uniform sampler1D worldPalette;
uniform sampler1D displayPalette;
varying vec4 f_color;
varying vec2 f_uv;
varying vec3 f_coord;

void main(void)
{
    vec4 sampled = texture2D(tex, f_uv);
    vec4 sampled_color = vec4(0.0, 0.0, 0.0, 0.0);
    vec4 vertex_color = f_color;
    float index = sampled.r;
    vec4 palval = texture1D(worldPalette, index);
    vec4 palvald = texture1D(displayPalette, index);
    vec4 blend = vec4(1.0, 1.0, 1.0, 1.0);

    float transparency = 1.0;
    if (index == 0.0)
        discard;
    sampled_color = vec4(palvald.r, palvald.g, palvald.b, transparency);

    gl_FragColor = sampled_color * vertex_color * blend;
}
