uniform sampler2D texPos;
uniform sampler2D texNormal;

uniform vec2 iResolution;

uniform vec4 occluderPosition;

in vec4 f_color;
in vec2 f_uv;
in vec3 f_coord;
layout(location = 0) out vec4 fragColor;

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

// https://www.shadertoy.com/view/4djSDy
float sphOcclusion( in vec3 pos, in vec3 nor, in vec4 sph )
{
    vec3  di = sph.xyz - pos;
    float l  = length(di);
    float nl = dot(nor,di/l);
    float h  = l/sph.w;
    float h2 = h*h;
    float k2 = 1.0 - h2*nl*nl;

    // above/below horizon
    // EXACT: Quilez - https://iquilezles.org/articles/sphereao
    float res = max(0.0,nl)/h2;
    
    // intersecting horizon 
    //if( k2 > 0.001 ) 
    //{
    //    #if 1
    //        // EXACT : Lagarde/de Rousiers - https://seblagarde.files.wordpress.com/2015/07/course_notes_moving_frostbite_to_pbr_v32.pdf
    //        res = nl*acos(-nl*sqrt( (h2-1.0)/(1.0-nl*nl) )) - sqrt(k2*(h2-1.0));
    //        res = res/h2 + atan( sqrt(k2/(h2-1.0)));
    //        res /= 3.141593;
    //    #else
    //        // APPROXIMATED : Quilez - https://iquilezles.org/articles/sphereao
    //        res = (nl*h+1.0)/h2;
    //        res = 0.33*res*res;
    //    #endif
    //}

    return clamp(res, 0.0, 1.0);
}

void main(void)
{
    vec2 fragCoord = gl_FragCoord.xy;

    // coordinate
    vec2 uv = fragCoord/(iResolution.xy);
    vec2 coord = fragCoord/(iResolution.y);

	vec3 pos = texture(texPos, uv).xyz;
	vec3 normal = decode_octahedron(texture(texNormal, uv).xy);

	//float occ = 1.0 - sphOcclusion(pos, normal, occluderPosition);

	//vec3 sphereDir = normalize(occluderPosition.xyz - pos.xyz);
	//float NdotL = max(dot(normal, sphereDir), 0.0);    
   // float occ = smoothstep(0.0, occluderPosition.w, NdotL);

    vec3 direction = normalize(occluderPosition.xyz - pos.xyz);
    float cosTheta = dot(normal, direction);
    float distance = length(occluderPosition.xyz - pos.xyz);
    float solidAngle =  (1.0 - cos(atan(occluderPosition.w / distance))) * smoothstep(0.0, occluderPosition.w, occluderPosition.w - distance);
    float integralSolidAngle = cosTheta * solidAngle;

    float occ = 1.0 - integralSolidAngle * 0.99;
	//occ = occ * 0.5 + 0.5;

	const float DITHER_LUT[16] = {
			0, 4, 1, 5,
			6, 2, 7, 3,
			1, 5, 0, 4,
			7, 3, 6, 2
		};

		int wrap_x = int(mod(gl_FragCoord.x, 3.0));
		int wrap_y = int(mod(gl_FragCoord.y, 3.0));
		int wrap_index = wrap_x + wrap_y * 4;
		occ = min(occ + DITHER_LUT[wrap_index] / 255.0, 1.0);

	//if(occ < 1.0/32.0)
		//discard;

    fragColor = vec4(occ, occ, occ, 1.0);
}