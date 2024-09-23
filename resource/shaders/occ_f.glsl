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

void main(void)
{
    vec2 fragCoord = gl_FragCoord.xy;

    // coordinate
    vec2 uv = fragCoord/(iResolution.xy);
    vec2 coord = fragCoord/(iResolution.y);

	float depth = texture(texDepth, uv).x;
	vec3 pos = get_view_position(depth, uv);
	vec3 normal = decode_octahedron(texture(texNormal, uv).xy);

    vec3 direction = normalize(volumePosition.xyz - pos.xyz);
    float cosTheta = dot(normal, direction);
    float distance = length(volumePosition.xyz - pos.xyz);
    float solidAngle =  (1.0 - cos(atan(volumeRadius / distance))) * smoothstep(0.0, volumeRadius, volumeRadius - distance);
    float integralSolidAngle = cosTheta * solidAngle;

    float occ = 1.0 - integralSolidAngle * 0.8;
	if(occ < 1.0/32.0)
		discard;

	const float DITHER_LUT[16] = float[16](
			0, 4, 1, 5,
			6, 2, 7, 3,
			1, 5, 0, 4,
			7, 3, 6, 2
	);

	int wrap_x = int(mod(gl_FragCoord.x, 3.0));
	int wrap_y = int(mod(gl_FragCoord.y, 3.0));
	int wrap_index = wrap_x + wrap_y * 4;
	occ = min(occ + DITHER_LUT[wrap_index] / 255.0, 1.0);

    fragColor = vec4(occ, occ, occ, 1.0);
}