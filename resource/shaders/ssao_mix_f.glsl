uniform sampler2D tex;
uniform sampler2D tex2;
uniform vec2 iResolution;
uniform float param1;
uniform float param2;
uniform float param3;
in vec4 f_color;
in vec2 f_uv;
in vec3 f_coord;
out vec4 fragColor;

//#define SSAO_CHECK_LEVELS
//#define SSAO_COMPARISON

void main(void)
{
#ifdef SSAO_CHECK_LEVELS
    vec4 sampled_color = vec4(0.5, 0.5, 0.5, 1.0);
#else
    vec4 sampled_color = texture(tex2, f_uv);
#endif
    
    // The background we're applying to
    vec4 color = texture(tex, f_uv);

    float scaleFactor = 1.1;

#ifdef SSAO_COMPARISON
    if (f_uv.x < 0.5) {
        fragColor = sampled_color;
    }
    else
    {
#ifdef SSAO_CHECK_LEVELS
        if (f_uv.y > 0.5)
        {
            fragColor = vec4(scaleFactor * color.rgb * vec3(0.5, 0.5, 0.5), 1.0);
        }
        else
#endif
        {
            fragColor = vec4(scaleFactor * color.rgb * sampled_color.rgb, 1.0);
        }
    }
#else
    fragColor = vec4(scaleFactor * color.rgb * sampled_color.rgb, sampled_color.a);
#endif

    fragColor.rgb = pow(fragColor.rgb, vec3(1.0/param3));
}