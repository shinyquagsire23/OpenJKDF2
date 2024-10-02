in vec3 coord3d;
in vec4 v_color;
in float v_light;
in vec4 v_uv;
in vec3 v_normal;

in vec3 coordVS;

uniform mat4 mvp;
out vec4 f_color;
out float f_light;
out vec4 f_uv;
out vec3 f_coord;
out vec3 f_normal;
out float f_depth;

uniform mat4 modelMatrix;
uniform int uv_mode;
uniform vec2 iResolution;

uniform vec4 texgen_params;
uniform vec2 uv_offset;

noperspective out vec2 f_uv_affine;

vec2 do_horizon_uv(inout vec4 clip_pos)
{
	vec2 projXY = vec2(0.5, 0.5) * clip_pos.xy;
	projXY = projXY.xy * iResolution.xy * (texgen_params.x / clip_pos.w);

	vec2 uv;
	uv.x = projXY.x * texgen_params.y + (projXY.y * -texgen_params.z);
	uv.y = projXY.y * texgen_params.y + (projXY.x *  texgen_params.z);
	
	clip_pos.z = clip_pos.w - 0.25/64.0;
	
	return (uv + uv_offset.xy) / 128.0; // todo: from mat
}

void main(void)
{
	vec4 viewPos = modelMatrix * vec4(coord3d, 1.0);
    vec4 pos = mvp * viewPos;
	f_normal = normalize(mat3(modelMatrix) * v_normal.xyz);

 	f_depth = pos.w / 128.0;
    gl_Position = pos;
    f_color = v_color.bgra;
    f_uv = v_uv;
	f_uv.xy += uv_offset.xy;
	f_uv_affine = v_uv.xy;
	if(uv_mode == 6) // 6 = RD_TEXTUREMODE_HORIZON
		f_uv_affine = do_horizon_uv(gl_Position);
	f_coord = viewPos.xyz;
    f_light = v_light;
}
