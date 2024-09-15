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
	vec4 color = texture(tex, f_uv.xy);
	vec4 vel = texture(tex2, f_uv.xy);
	float z = vel.z;

	fragColor = vec4(color.rgb, 1.0);

	// todo: pre-dilate with seperable filters
	{
		vec2 poisson[7] = {  
			vec2( 0.527837,-0.085868),
			vec2(-0.040088, 0.536087),
			vec2(-0.670445,-0.179949),
			vec2(-0.419418,-0.616039),
			vec2( 0.440453,-0.639399),
			vec2(-0.757088, 0.349334),
			vec2( 0.574619, 0.685879)
		};

		for (int n = 0; n < 7; n++)
		{	    
			vec2 uv = poisson[n] * 0.0666 * min(1.0, (1.0 - z) * (1.0 - z));
			vec4 ivel = texture(tex2, uv+ f_uv.xy);
			if(length(vel.xy) < length(ivel.xy) && vel.z > ivel.z)
				vel = ivel;
		}
	}
    
	// early out
	float sqLen = dot(vel, vel);
	if (dot(vel, vel) < 0.0001)
		return;

	float len = sqrt(sqLen);
	if(len > 0.0)
		vel /= len;
	vel *= min(len, 0.4) * param1;

	vec4 acc = vec4(0.0);
	for(int i = 0; i < 8; ++i)
	{
		float dist = (i / 8.0) - 0.5;
		vec2 uv = vel.xy * vec2(dist) + f_uv.xy;
		vec4 icolor = texture(tex, uv.xy);
		vec4 ivel = texture(tex2, uv);

		acc.rgb += icolor.rgb;
		if(param2 > 0.0) // already got an alpha mask
			acc.w += icolor.w;
		else
			acc.w += min(1.0, 100000.0 * dot(ivel.xy, ivel.xy));
	}

	if (acc.w > 0.0)
	{
		acc *= 1.0 / 8.0;
		acc.w = min(1.0, acc.w) * 2.0;

		if(param2 > 0.0) // include previous alpha
			fragColor.rgb = mix(color.rgb, acc.rgb, min(acc.w + min(1.0, color.w), 1.0));
		else
			fragColor.rgb = mix(color.rgb, acc.rgb, min(acc.w, 1.0));
	}

	fragColor.w = param2 > 0.0 ? 1.0 : acc.w;
}
