uniform sampler2D texDepth;
uniform sampler2D texNormal;

uniform vec2 iResolution;

uniform uint   volumeFlags;
uniform vec3   volumePosition;
uniform float  volumeRadius;
uniform vec3   volumeColor;
uniform mat4x4 volumeInvMatrix;

uniform vec3 cameraLB;
uniform vec3 cameraLT;
uniform vec3 cameraRB;
uniform vec3 cameraRT;

in vec4 f_color;
in vec2 f_uv;
in vec3 f_coord;
layout(location = 0) out vec4 fragColor;


vec3 get_camera_frustum_ray(vec2 uv)
{
	//vec3 b = mix(cameraLB.xyz, cameraRB.xyz, uv.x);
	//vec3 t = mix(cameraLT.xyz, cameraRT.xyz, uv.x);
	//return mix(b, t, uv.y);
	
	// barycentric lerp
	return ((1.0 - uv.x - uv.y) * cameraLB.xyz + (uv.x * cameraRB.xyz + (uv.y * cameraLT.xyz)));
}

// Returns the world position from linear depth and a frustum ray
vec3 get_view_position_from_depth(vec3 cam_vec, float linear_depth)
{
	return cam_vec.xyz * linear_depth;
}

vec3 get_view_position(float linear_depth, vec2 uv)
{
	vec3 cam_vec = get_camera_frustum_ray(uv).xyz;
	return get_view_position_from_depth(cam_vec, linear_depth);
}


vec2 oct_wrap(vec2 v)
{
	vec2 signs;
	signs.x = v.x >= 0.0 ? 1.0 : -1.0;
	signs.y = v.y >= 0.0 ? 1.0 : -1.0;
    return (1.0 - abs(v.yx)) * (signs);
}

vec3 decode_octahedron(vec2 p)
{
	p = p * 2.0 - 1.0;

	vec3 n;
    n.z = 1.0 - abs(p.x) - abs(p.y);
    n.xy = n.z >= 0.0 ? p.xy : oct_wrap( p.xy );
    return normalize(n);
}


float get_bayer_4x4_signed(ivec2 coord)
{
	mat4 bayerIndex = mat4(
		vec4(00.0/16.0, 12.0/16.0, 03.0/16.0, 15.0/16.0),
		vec4(08.0/16.0, 04.0/16.0, 11.0/16.0, 07.0/16.0),
		vec4(02.0/16.0, 14.0/16.0, 01.0/16.0, 13.0/16.0),
		vec4(10.0/16.0, 06.0/16.0, 09.0/16.0, 05.0/16.0)
	);

	return bayerIndex[coord.x % 4][coord.y % 4] * 2.0 - 1.0;
}

float apply_bayer_dither(float value, ivec2 coord, float steps)
{
	float rcp_steps = 1.0 / (steps - 1.0);
	float black_limit = 0.5 * (rcp_steps);
	float biggest = 0.75 * ((1.0 + rcp_steps) - 1.0);

	float bayer = get_bayer_4x4_signed(coord);
	return bayer * min(value + black_limit, biggest) + value;
}

// https://seblagarde.wordpress.com/2014/12/01/inverse-trigonometric-functions-gpu-optimization-for-amd-gcn-architecture/
// max absolute error 1.3x10^-3
// Eberly's odd polynomial degree 5 - respect bounds
// 4 VGPR, 14 FR (10 FR, 1 QR), 2 scalar
// input [0, infinity] and output [0, PI/2]
float atanPos(float x) 
{ 
    float t0 = (x < 1.0) ? x : 1.0f / x;
    float t1 = t0 * t0;
    float poly = 0.0872929;
    poly = -0.301895 + poly * t1;
    poly = 1.0f + poly * t1;
    poly = poly * t0;
    return (x < 1.0) ? poly : 1.570796 - poly;
}

// 4 VGPR, 16 FR (12 FR, 1 QR), 2 scalar
// input [-infinity, infinity] and output [-PI/2, PI/2]
float atanFast(float x) 
{     
    float t0 = atanPos(abs(x));     
    return (x < 0.0) ? -t0: t0; 
}

void main(void)
{
	vec2 fragCoord = gl_FragCoord.xy;

	// coordinate
	vec2 uv = fragCoord/(iResolution.xy);
	vec2 coord = fragCoord/(iResolution.y);

	float depth = texture(texDepth, uv).x;
	vec3 pos = get_view_position(depth, uv);
	vec3 normal = decode_octahedron(texture(texNormal, uv).xy);

	vec3 direction = (volumePosition.xyz - pos.xyz);
	float distance = length(volumePosition.xyz - pos.xyz);
	if(distance > 1e-6)
		direction /= distance;

	float cosTheta = max(0.0, dot(normal, direction));
	float solidAngle = (1.0 - cos(atanFast(volumeRadius / distance)));
	float falloff = smoothstep(0.0, volumeRadius, volumeRadius - distance);
	float integralSolidAngle = cosTheta * solidAngle * falloff;

	float occ = 1.0 - integralSolidAngle * 0.8;
#ifdef HIGHCOLOR
	if(occ >= 31.0 / 32.0)
		discard;
	occ = apply_bayer_dither(occ, ivec2(fragCoord), 32);
#else
	if(occ >= 1023.0 / 1024.0)
		discard;
#endif

	fragColor = vec4(occ, occ, occ, 1.0);
}