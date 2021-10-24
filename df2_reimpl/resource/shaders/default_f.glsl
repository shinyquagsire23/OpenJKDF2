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
    vec4 sampled = texture2D(tex, f_uv);
    vec4 sampled_color = vec4(0.0, 0.0, 0.0, 0.0);
    vec4 vertex_color = f_color;
    float index = sampled.r;
    vec4 palval = texture2D(worldPalette, vec2(index, 0.5));
    vec4 blend = vec4(1.0, 1.0, 1.0, 1.0);

    if (tex_mode == 0)
    {
        sampled_color = vec4(sampled.b, sampled.g, sampled.r, sampled.a);
    }
    else if (tex_mode == 1)
    {
        sampled_color = vec4(sampled.r, sampled.g, sampled.b, sampled.a);
    }
    else if (tex_mode == 2)
    {
        float transparency = sampled.a;
        if (sampled.r == 1.0 && sampled.g == 0.0 && sampled.b == 1.0)
            transparency = 0.0;
        sampled_color = vec4(sampled.b, sampled.g, sampled.r, transparency);
    }
    else if (tex_mode == 3)
    {
        sampled_color = vec4(1.0, 1.0, 1.0, 1.0);
    }
    else if (tex_mode == 4)
    {
        float transparency = 1.0;
        if (index == 0.0)
            discard;
        sampled_color = vec4(palval.r, palval.g, palval.b, transparency);
    }

    if (blend_mode == 5)
    {
        blend = vec4(1.0, 1.0, 1.0, 1.0);
        if (sampled_color.a < 0.1)
            discard;
    }
    fragColor = sampled_color * vertex_color * blend;
}
