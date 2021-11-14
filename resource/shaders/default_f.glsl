uniform sampler2D tex;
uniform sampler2D worldPalette;
uniform int tex_mode;
uniform int blend_mode;
in vec4 f_color;
in vec2 f_uv;
in vec3 f_coord;
out vec4 fragColor;

void main(void)
{
    vec4 sampled = texture(tex, f_uv);
    vec4 sampled_color = vec4(1.0, 1.0, 1.0, 1.0);
    vec4 vertex_color = f_color;
    float index = sampled.r;
    vec4 palval = texture(worldPalette, vec2(index, 0.5));

    if (tex_mode == 1)
    {
        float transparency = 1.0;
        if (index == 0.0)
            discard;
        sampled_color = vec4(palval.r, palval.g, palval.b, transparency);
    }

    if (blend_mode == 5)
    {
        if (sampled_color.a < 0.1)
            discard;
    }
    fragColor = sampled_color * vertex_color;
}
