uniform sampler2D tex;
uniform vec2 iResolution;
uniform float param1;
uniform float param2;
uniform float param3;
in vec4 f_color;
in vec2 f_uv;
in vec3 f_coord;
out vec4 fragColor;

void main(void)
{
	// water distortion
	vec2 uv = f_uv;
	if(param1 > 0.0)
	{
		float ar = iResolution.x / iResolution.y;
		vec2 cycle = vec2(1.0, ar) * 3.141592 * 5.0;
		vec2 amp = vec2(1.0, ar) / 300.0;
		uv = uv.xy + (sin(uv.yx * cycle.xy + param1) * amp.xy) * (1.0 - amp.xy * 2.0) + amp.xy;
	}

    vec4 sampled_color = texture(tex, uv);

	// when dithering, try to smooth it out with a classic voodoo style filter
	//if(param2 > 0.0)
	//{
	//	vec2 sourceSize = textureSize(tex, 0).xy;
	//	vec4 pixel00 = sampled_color;
	//	vec4 pixel01 = texture(tex, uv + vec2(0, 1.0 / sourceSize.y));
	//	vec4 pixel11 = texture(tex, uv + vec2(1.0 / sourceSize.x, 1.0 / sourceSize.y));
	//	vec4 pixel10 = texture(tex, uv + vec2(1.0 / sourceSize.x, 0));
	//	
	//	vec4 diff0 = clamp(pixel01 - pixel00, -32.0/255.0, 32.0/255.0);
	//	vec4 diff1 = clamp(pixel11 - pixel00, -32.0/255.0, 32.0/255.0);
	//	vec4 diff2 = clamp(pixel10 - pixel00, -32.0/255.0, 32.0/255.0);
	//	
	//	sampled_color = (pixel00 + (diff0 + diff1 + diff2) / 3.0);
	//}
    fragColor = sampled_color;
    fragColor.rgb = pow(fragColor.rgb, vec3(1.0/param3));
	fragColor.w = 1.0;
}
