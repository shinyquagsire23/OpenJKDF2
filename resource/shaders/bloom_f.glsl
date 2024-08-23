uniform sampler2D tex;
uniform vec2 iResolution;
uniform float param1;
uniform float param2;
uniform float param3;

in vec2 f_uv;

out vec4 fragColor;

void main(void)
{
	vec2 PixSize = param1 / iResolution.xy;
    
	// 6x6 downscale/upscale
    vec4 s0 = texture(tex, f_uv.xy + vec2( 0.000000000, 0.000000000) * PixSize.xy, 0.0);
	vec4 s1 = texture(tex, f_uv.xy + vec2( 0.604077935, 0.000000000) * PixSize.xy, 0.0);
	vec4 s2 = texture(tex, f_uv.xy + vec2( 0.000000000, 0.604077935) * PixSize.xy, 0.0);
	vec4 s3 = texture(tex, f_uv.xy + vec2(-0.604077935, 0.000000000) * PixSize.xy, 0.0);
	vec4 s4 = texture(tex, f_uv.xy + vec2( 0.000000000,-0.604077935) * PixSize.xy, 0.0);		
	vec4 s5 = texture(tex, f_uv.xy + vec2( 0.604077935, 0.604077935) * PixSize.xy, 0.0);
	vec4 s6 = texture(tex, f_uv.xy + vec2(-0.604077935, 0.604077935) * PixSize.xy, 0.0);
	vec4 s7 = texture(tex, f_uv.xy + vec2( 0.604077935,-0.604077935) * PixSize.xy, 0.0);
	vec4 s8 = texture(tex, f_uv.xy + vec2(-0.604077935,-0.604077935) * PixSize.xy, 0.0);
		
	vec4 Color = s0 * 0.145904019;
	Color += 0.11803490998 * (s1 + s2 + s3 + s4);
	Color += 0.09548908532 * (s5 + s6 + s7 + s8);

	// simple kawase
	//const vec2 s = vec2(-1,1);
	//const vec2 a = vec2(0,2);
	//vec4 Color = (texture(tex, f_uv + PixSize.xy * s.xx, 0.0) +
	// 			  texture(tex, f_uv + PixSize.xy * s.yx, 0.0) +
	// 			  texture(tex, f_uv + PixSize.xy * s.xy, 0.0) +
	// 			  texture(tex, f_uv + PixSize.xy * s.yy, 0.0)) / 6.0 +
	// 			 (texture(tex, f_uv + PixSize.xy * a.xy, 0.0) +
	// 			  texture(tex, f_uv - PixSize.xy * a.xy, 0.0) +
	// 			  texture(tex, f_uv + PixSize.xy * a.yx, 0.0) +
	// 			  texture(tex, f_uv - PixSize.xy * a.yx, 0.0)) / 12.0;
	
	fragColor = vec4(Color.rgb, param3);
}
