uniform sampler2D texPos;
uniform sampler2D texLight;
uniform sampler2D texNormal;
uniform sampler2D texDiffuse;
uniform sampler2D texPalette;
uniform sampler2D tex;

uniform vec2 iResolution;

uniform int texMode;

uniform vec3 decalColor;
uniform uint decalFlags;
uniform float decalAngleFade;
uniform mat4x4 decalMatrix;

uniform vec3 colorEffects_tint;
uniform vec3 colorEffects_filter;
uniform float colorEffects_fade;
uniform vec3 colorEffects_add;

uniform vec3 cameraLB;
uniform vec3 cameraLT;
uniform vec3 cameraRB;
uniform vec3 cameraRT;

in vec4 f_color;
in vec2 f_uv;
in vec3 f_coord;
layout(location = 0) out vec4 fragColor;
layout(location = 1) out vec4 fragColorEmissive;

#define TEX_MODE_TEST 0
#define TEX_MODE_WORLDPAL 1
#define TEX_MODE_BILINEAR 2
#define TEX_MODE_16BPP 5
#define TEX_MODE_BILINEAR_16BPP 6


#ifdef HAS_TEXTUREGATHER
vec4 impl_textureGather(sampler2D tex, vec2 uv)
{
    return textureGather(tex, uv);
}
#else
float modI(float a,float b) {
    float m=a-floor((a+0.5)/b)*b;
    return floor(m+0.5);
}

vec4 impl_textureGather(sampler2D tex, vec2 uv)
{
    ivec2 idims = textureSize(tex,0) - ivec2(1, 1);
    vec2 dims = vec2(idims);

    ivec2 base = ivec2(dims*uv);
    if (base.x < 0) {
        //base.x = -base.x;
    }
    if (base.y < 0) {
        //base.y = -base.y;
    }

    base.x = int(modI(float(base.x), dims.x));
    base.y = int(modI(float(base.y), dims.y));

    return vec4(texelFetch(tex,base+ivec2(0,1),0).x,
        texelFetch(tex,base+ivec2(1,1),0).x,
        texelFetch(tex,base+ivec2(1,0),0).x,
        texelFetch(tex,base+ivec2(0,0),0).x
    );
}
#endif


void clip(vec3 v)
{
   if (v.x > 1.0 || v.x < 0.0 ) { discard; }
   if (v.y > 1.0 || v.y < 0.0 ) { discard; }
   if (v.z > 1.0 || v.z < 0.0 ) { discard; }
}

vec3 blackbody(float t)
{
    t *= 3000.0;
    
    float u = ( 0.860117757 + 1.54118254e-4 * t + 1.28641212e-7 * t*t ) 
            / ( 1.0 + 8.42420235e-4 * t + 7.08145163e-7 * t*t );
    
    float v = ( 0.317398726 + 4.22806245e-5 * t + 4.20481691e-8 * t*t ) 
            / ( 1.0 - 2.89741816e-5 * t + 1.61456053e-7 * t*t );

    float x = 3.0*u / (2.0*u - 8.0*v + 4.0);
    float y = 2.0*v / (2.0*u - 8.0*v + 4.0);
    float z = 1.0 - x - y;
    
    float Y = 1.0;
    float X = Y / y * x;
    float Z = Y / y * z;

    mat3 XYZtoRGB = mat3(3.2404542, -1.5371385, -0.4985314,
                        -0.9692660,  1.8760108,  0.0415560,
                         0.0556434, -0.2040259,  1.0572252);

    return max(vec3(0.0), (vec3(X,Y,Z) * XYZtoRGB) * pow(t * 0.0004, 4.0));
}


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

#ifdef CAN_BILINEAR_FILTER
vec4 bilinear_paletted(vec2 uv)
{
    // Get texture size in pixels:
    vec2 colorTextureSize = vec2(textureSize(tex, 0));

    // Convert UV coordinates to pixel coordinates and get pixel index of top left pixel (assuming UVs are relative to top left corner of texture)
    vec2 pixCoord = uv * colorTextureSize - 0.5f;    // First pixel goes from -0.5 to +0.4999 (0.0 is center) last pixel goes from (size - 1.5) to (size - 0.5000001)
    vec2 originPixCoord = floor(pixCoord);              // Pixel index coordinates of bottom left pixel of set of 4 we will be blending

    // For Gather we want UV coordinates of bottom right corner of top left pixel
    vec2 gUV = (originPixCoord + 1.0f) / colorTextureSize;

    vec4 gIndex   = impl_textureGather(tex, gUV);

    vec4 c00   = texture(texPalette, vec2(gIndex.w, 0.5));
    vec4 c01 = texture(texPalette, vec2(gIndex.x, 0.5));
    vec4 c11  = texture(texPalette, vec2(gIndex.y, 0.5));
    vec4 c10 = texture(texPalette, vec2(gIndex.z, 0.5));

    /*if (blend_mode == D3DBLEND_SRCALPHA || blend_mode == D3DBLEND_INVSRCALPHA) {
        if (gIndex.x == 0.0) {
            c01.a = 0.0;
        }
        if (gIndex.y == 0.0) {
            c11.a = 0.0;
        }
        if (gIndex.z == 0.0) {
            c10.a = 0.0;
        }
        if (gIndex.w == 0.0) {
            c00.a = 0.0;
        }
    }*/

    vec2 filterWeight = pixCoord - originPixCoord;
 
    // Bi-linear mixing:
    vec4 temp0 = mix(c01, c11, filterWeight.x);
    vec4 temp1 = mix(c00, c10, filterWeight.x);
    vec4 blendColor = mix(temp1, temp0, filterWeight.y);

    return vec4(blendColor.r, blendColor.g, blendColor.b, blendColor.a);
}
#endif


void main(void)
{
    vec2 fragCoord = gl_FragCoord.xy;// f_uv*iResolution.xy;

    // coordinate
    vec2 uv = fragCoord/(iResolution.xy);
    vec2 coord = fragCoord/(iResolution.y);

	//vec3 pos = texture(texPos, uv).xyz;// coord*vec2(iResolution.y/iResolution.x,1.0)).xyz;
	float depth = texture(texPos, uv).x;
	vec3 pos = get_view_position(depth, uv);
	vec4 objectPosition = decalMatrix * vec4(pos.xyz, 1.0);

	vec3 normal = decode_octahedron(texture(texNormal, uv).xy);
	vec4 objectNormal = decalMatrix * vec4(normal.xyz, 0.0);
	objectNormal.xyz = normalize(objectNormal.xyz);

	vec3 falloff = 0.5f - abs(objectPosition.xyz);
	float alpha = 1.0;
	if( any(lessThanEqual(falloff, vec3(0.0))) )
	{
		alpha = 0.0;
		discard;//clip(0.5 - abs(objectPosition.xyz));
	}
	//if (objectNormal.y < 0.0)
		//discard;
	//clip(objectPosition.xyz);

	vec2 decalTexCoord = objectPosition.xz + 0.5;
	vec4 sampled = texture(tex, decalTexCoord);
	float index = sampled.r;
    vec4 palval = texture(texPalette, vec2(index, 0.5));

	vec4 emissive = vec4(0.0, 0.0, 0.0, 1.0);

	vec4 sampled_color = vec4(0.0);
	if (texMode == TEX_MODE_TEST) {
        sampled_color = vec4(1.0, 1.0, 1.0, 1.0);
    }
    else if (texMode == TEX_MODE_16BPP
    || texMode == TEX_MODE_BILINEAR_16BPP
    )
    {
        sampled_color = vec4(sampled.b, sampled.g, sampled.r, sampled.a);
    }
    else if (texMode == TEX_MODE_WORLDPAL
#ifndef CAN_BILINEAR_FILTER
    || texMode == TEX_MODE_BILINEAR
#endif
    )
    {
        if (index == 0.0)
            discard;
        sampled_color = palval;
    }
#ifdef CAN_BILINEAR_FILTER
    else if (texMode == TEX_MODE_BILINEAR)
    {
        sampled_color = bilinear_paletted(decalTexCoord);
        if (sampled_color.a < 0.01)
            discard;
    }
#endif

	// omfg I hate glsl
	bool isInside = mod(decalFlags, 2.0) > 0.;
	bool isHeat = mod(floor(decalFlags / 2.0), 2.0) > 0.;
	bool isAdditive = mod(floor(decalFlags / 4.0), 2.0) > 0.;
	bool isRgbAlpha = mod(floor(decalFlags / 8.0), 2.0) > 0.;

	if(isRgbAlpha)
	{
		sampled_color.a = max(sampled_color.r, max(sampled_color.g, sampled_color.b));
	}

	if(isHeat)
	{
		//sampled_color.rgb*=sampled_color.rgb;
		sampled_color.rgb *= decalColor.rgb;
		//sampled_color.rgb = pow(decalColor.rgb, sampled_color.rgb * 100.0f);

		//sampled_color.rgb = 1.0 - exp(-sampled_color.rgb);
		sampled_color.rgb = blackbody(sampled_color.r);// smoothstep(decalColor.rgb, vec3(0.0), 1.0 - sampled_color.rgb);
		emissive.rgb = sampled_color.rgb;
	}
	else
	{
		sampled_color.rgb *= decalColor.rgb;
	}

	if(!isAdditive)
	{
		vec3 light = texture(texLight, uv).xyz; // contains color * light
		vec3 color = texture(texDiffuse, uv).xyz; // contains only color

		// remove the color component, leaving only lighting
		light /= max(vec3(0.001), color.xyz);
		light = clamp(light.xyz, vec3(0.0), vec3(1.0));

		sampled_color.rgb *= light.rgb;
	}
	else
	{
		emissive.rgb = sampled_color.rgb;
	}
	
	sampled_color.rgb += colorEffects_add.rgb;

	vec3 tint = normalize(colorEffects_tint + 1.0) * sqrt(3.0);
	
    sampled_color.r *= tint.r;
    sampled_color.g *= tint.g;
    sampled_color.b *= tint.b;
	
    sampled_color.r *= colorEffects_fade;
    sampled_color.g *= colorEffects_fade;
    sampled_color.b *= colorEffects_fade;
	
    sampled_color.r *= colorEffects_filter.r;
    sampled_color.g *= colorEffects_filter.g;
    sampled_color.b *= colorEffects_filter.b;

	// fade out by angle
	if(decalAngleFade > 0.0)
	{
		float angleDiff = (objectNormal.y - decalAngleFade) / (1.0 - decalAngleFade);
		sampled_color.a *= clamp(angleDiff, 0.0, 1.0);
	}

	//if(objectNormal.y < decalAngleFade)
		//discard;

	sampled_color.a *= clamp(4.0 * falloff.y, 0.0, 1.0);

	//sampled_color.xyz = vec3(max(0.0, objectNormal.y));
	//sampled_color.a = (1.0);
	
	//sampled_color = vec4(1.0);
    fragColor = (sampled_color);
	fragColorEmissive = vec4(emissive.rgb, sampled_color.a);
}