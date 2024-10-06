uniform sampler2D tex;
uniform sampler2D tex2;
uniform vec2 iResolution;
uniform float param1;
uniform float param2;
uniform float param3;

in vec2 f_uv;

out vec4 fragColor;

void main(void)
{
	vec4 sampled = texture(tex, f_uv);
    vec4 sampled_color = vec4(1.0, 1.0, 1.0, 1.0);

    float index = sampled.r;
    if (param1 < 5)
    {
        sampled_color = texture(tex2, vec2(index, 0.5));
    }
    else
    {
        sampled_color = vec4(sampled.b, sampled.g, sampled.r, sampled.a);
    }

    fragColor = sampled_color;
}
