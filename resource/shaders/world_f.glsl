#ifdef GL_ARB_texture_gather
#define HAS_TEXTUREGATHER
#endif

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

#define LIGHT_DIVISOR (3.0)

#define TEX_MODE_TEST 0
#define TEX_MODE_WORLDPAL 1
#define TEX_MODE_BILINEAR 2
#define TEX_MODE_16BPP 5
#define TEX_MODE_BILINEAR_16BPP 6

#define D3DBLEND_ONE             (2)
#define D3DBLEND_SRCALPHA        (5)
#define D3DBLEND_INVSRCALPHA     (6)

uniform sampler2D tex;
uniform sampler2D texEmiss;
uniform sampler2D worldPalette;
uniform sampler2D worldPaletteLights;
uniform sampler2D displacement_map;
uniform int tex_mode;
uniform int blend_mode;
uniform vec3 colorEffects_tint;
uniform vec3 colorEffects_filter;
uniform float colorEffects_fade;
uniform vec3 colorEffects_add;
uniform vec3 emissiveFactor;
uniform vec4 albedoFactor;
uniform float displacement_factor;
uniform float light_mult;
uniform vec2 iResolution;
uniform int enableDither;

#ifdef FOG
uniform int fogEnabled;
uniform vec4 fogColor;
uniform float fogStart;
uniform float fogEnd;
#endif

in vec4 f_color;
in float f_light;
in vec4 f_uv;
in vec3 f_coord;
in vec3 f_normal;
in float f_depth;

noperspective in vec2 f_uv_affine;

uniform mat4 modelMatrix;

uniform int uv_mode;
uniform vec4 fillColor;

uniform int lightMode;
uniform int  ambientMode;
uniform vec3 ambientColor;
uniform vec4 ambientSH[3];
uniform vec3 ambientDominantDir;
uniform vec3 ambientSG[8];
uniform vec4 ambientSGBasis[8];

struct light
{
	vec4  position;
	vec4  direction_intensity;
	vec4  color;
	int   type;
	uint  isActive;
	float falloffMin;
	float falloffMax;
	float angleX;
	float cosAngleX;
	float angleY;
	float cosAngleY;
	float lux;
	float padding0;
	float padding1;
};

uniform int numLights;
uniform lightBlock
{
	light lights[128];
};

// https://therealmjp.github.io/posts/sg-series-part-1-a-brief-and-incomplete-history-of-baked-lighting-representations/
// SphericalGaussian(dir) := Amplitude * exp(Sharpness * (dot(Axis, dir) - 1.0f))
struct SG
{
    vec3 Amplitude;
    vec3 Axis;
    float Sharpness;
};

SG DistributionTermSG(vec3 direction, float roughness)
{
    SG distribution;
    distribution.Axis = direction;
    float m2 = roughness * roughness;
    distribution.Sharpness = 2.0 / m2;
    distribution.Amplitude = vec3(1.0 / (3.141592 * m2));

    return distribution;
}

SG WarpDistributionSG(SG ndf, vec3 view)
{
    SG warp;
    warp.Axis = reflect(-view, ndf.Axis);
    warp.Amplitude = ndf.Amplitude;
    warp.Sharpness = ndf.Sharpness / (4.0 * max(dot(ndf.Axis, view), 0.1));
    return warp;
}

vec3 SGInnerProduct(SG x, SG y)
{
    float umLength = length(x.Sharpness * x.Axis + y.Sharpness * y.Axis);
    vec3 expo = exp(umLength - x.Sharpness - y.Sharpness) * x.Amplitude * y.Amplitude;
    float other = 1.0 - exp(-2.0 * umLength);
    return (2.0 * 3.141592 * expo * other) / umLength;
}

SG CosineLobeSG(vec3 direction)
{
    SG cosineLobe;
    cosineLobe.Axis = direction;
    cosineLobe.Sharpness = 2.133;
    cosineLobe.Amplitude = vec3(1.17);

    return cosineLobe;
}

vec3 SGIrradianceInnerProduct(SG lightingLobe, vec3 normal)
{
    SG cosineLobe = CosineLobeSG(normal);
    return max(SGInnerProduct(lightingLobe, cosineLobe), 0.0f);
}

vec3 SGIrradiancePunctual(SG lightingLobe, vec3 normal)
{
    float cosineTerm = clamp(dot(lightingLobe.Axis, normal), 0.0, 1.0);
    return cosineTerm * 2.0 * 3.141592 * (lightingLobe.Amplitude) / lightingLobe.Sharpness;
}

vec3 CalculateAmbientDiffuse(vec3 normal)
{
	vec3 ambientDiffuse = vec3(0.0);
	for(int sg = 0; sg < 8; ++sg)
	{
		SG lightSG;
		lightSG.Amplitude = ambientSG[sg].xyz;
		lightSG.Axis = ambientSGBasis[sg].xyz;
		lightSG.Sharpness = ambientSGBasis[sg].w;
	
		vec3 diffuse = SGIrradianceInnerProduct(lightSG, normal) / 3.141592;
		ambientDiffuse.xyz += diffuse;
	}
	return ambientDiffuse;
}

vec3 CalculateAmbientSpecular(vec3 normal, vec3 view, float roughness)
{
	//float m2 = roughness * roughness;
	//float nDotV = clamp(dot(normal.xyz, view.xyz), 0.0, 1.0);

	vec3 ambientSpecular = vec3(0.0);
	for(int sg = 0; sg < 8; ++sg)
	{
		SG ndf = DistributionTermSG(normal, roughness);
		SG warpedNDF = WarpDistributionSG(ndf, view);

		SG lightSG;
		lightSG.Amplitude = ambientSG[sg].xyz;
		lightSG.Axis = ambientSGBasis[sg].xyz;
		lightSG.Sharpness = ambientSGBasis[sg].w;

		float nDotL = clamp(dot(normal.xyz, warpedNDF.Axis.xyz), 0.0, 1.0);

		// NDF
		vec3 spec = SGInnerProduct(warpedNDF, lightSG);

		// no Geometry term

		// Fresnel
		//vec3 h = normalize(warpedNDF.Axis + view);
		//spec *= specColor + (1.0f - specColor) * pow((1.0f - clamp(dot(warpedNDF.Axis, h), 0.0, 1.0)), 5.0f);
		
		spec *= nDotL;
		ambientSpecular.xyz += spec / 3.141592;
	}
	return ambientSpecular;
}

float do_specular(vec3 lightDir, vec3 viewDir, vec3 normal, float shiny)
{
	vec3 h = normalize(lightDir + viewDir);
	float brdf = clamp(dot(h, normal), 0.0, 1.0);
	//brdf *= brdf; // x2
	//brdf *= brdf; // x4
	//brdf *= brdf; // x8
	brdf = pow(brdf, shiny) * (shiny + 8.0) / (8.0 * 3.141592);
	return brdf;
}

float do_fresnel(vec3 viewDir, vec3 normal, float f0)
{
	float fresnel = abs(1.0 - dot(normal, viewDir));
	fresnel *= fresnel;
	fresnel *= fresnel;
	return f0 + (1.0 - f0) * fresnel;
}

float do_half_lambert(float ndotl)
{
	ndotl = ndotl * 0.5f + 0.5f;
	return ndotl * ndotl;
}

// https://www.unrealengine.com/en-US/blog/physically-based-shading-on-mobile
vec3 do_env_brdf(vec3 viewDir, vec3 normal, vec3 f0, float roughness)
{
	const vec4 c0 = vec4(-1, -0.0275, -0.572, 0.022);
	const vec4 c1 = vec4(1, 0.0425, 1.04, -0.04);
	vec4 r = roughness * c0 + c1;
	float a004 = min( r.x * r.x, exp2( -9.28 * dot(normal, viewDir) ) ) * r.x + r.y;
	vec2 AB = vec2( -1.04, 1.04 ) * a004 + r.zw;
	return f0 * AB.x + AB.y;
}

layout(location = 0) out vec4 fragColor;
layout(location = 1) out vec4 fragColorEmiss;
#ifdef VIEW_SPACE_GBUFFER
layout(location = 2) out float fragColorDepth;
layout(location = 3) out vec2 fragColorNormal;
#else
layout(location = 2) out vec4 fragColorPos;
layout(location = 3) out vec4 fragColorNormal;
#endif
#ifdef VIEW_SPACE_GBUFFER
layout(location = 4) out vec4 fragColorDiffuse;

vec2 oct_wrap(vec2 v)
{
	vec2 signs;
	signs.x = v.x >= 0.0 ? 1.0 : -1.0;
	signs.y = v.y >= 0.0 ? 1.0 : -1.0;
    return (1.0 - abs(v.yx)) * (signs);
}

vec2 encode_octahedron(vec3 v)
{
    v /= abs(v.x) + abs(v.y) + abs(v.z);
    v.xy = v.z >= 0.0 ? v.xy : oct_wrap(v.xy);
    return clamp(v.xy, vec2(-1.0), vec2(1.0)) * 0.5 + 0.5;
}

#endif

float luminance(vec3 c_rgb)
{
    const vec3 W = vec3(0.2125, 0.7154, 0.0721);
    return dot(c_rgb, W);
}

vec3 normals(vec3 pos) {
    vec3 fdx = dFdx(pos);
    vec3 fdy = dFdy(pos);
    return normalize(cross(fdx, fdy));
}

mat3 construct_tbn(vec2 uv, vec3 vp_normal, vec3 adjusted_coords)
{
    vec3 n = normalize(vp_normal);

    vec3 dp1 = dFdx(adjusted_coords);
    vec3 dp2 = dFdy(adjusted_coords);
    vec2 duv1 = dFdx(uv.xy);
    vec2 duv2 = dFdy(uv.xy);

    vec3 dp2perp = cross(dp2, n);
    vec3 dp1perp = cross(n, dp1);

    vec3 t = dp2perp * duv1.x + dp1perp * duv2.x;
    vec3 b = dp2perp * duv1.y + dp1perp * duv2.y;

    float invmax = inversesqrt(max(dot(t, t), dot(b, b)));
    return mat3(t * invmax, b * invmax, n);
}

vec2 parallax_mapping(vec2 tc, vec3 vp_normal, vec3 adjusted_coords)
{
    /*if (f_coord.x < 0.5) {
        return tc;
    }*/

    // The injector world space view position is always considered (0, 0, 0):
    vec3 view_dir = -normalize(transpose(construct_tbn(tc, vp_normal, adjusted_coords)) * adjusted_coords);

    const float min_layers = 32.0;
    const float max_layers = 128.0;
    float num_layers = mix(max_layers, min_layers, abs(dot(vec3(0.0, 0.0, 1.0), view_dir)));

    float layer_depth = 1.0 / num_layers;
    float current_layer_depth = 0.0;
    vec2 shift_per_layer = (view_dir.xy / view_dir.z) * displacement_factor;
    vec2 d_tc = shift_per_layer / num_layers;

    vec2 current_tc = tc;
    float current_sample = texture(displacement_map, current_tc).r;

    while(current_layer_depth < current_sample) {
        current_tc -= d_tc;
        current_sample = texture(displacement_map, current_tc).r;
        current_layer_depth += layer_depth;
    }

    vec2 prev_tc = current_tc + d_tc;

    float after_col_depth = current_sample - current_layer_depth;
    float before_col_depth = texture(displacement_map, prev_tc).r - current_layer_depth + layer_depth;

    float a = after_col_depth / (after_col_depth - before_col_depth);
    vec2 adj_tc = mix(current_tc, prev_tc, a);

    return adj_tc;
}

#ifdef CAN_BILINEAR_FILTER
vec4 bilinear_paletted(vec2 uv)
{
    // Get texture size in pixels:
    vec2 colorTextureSize = vec2(textureSize(tex, 0));

    // Convert UV coordinates to pixel coordinates and get pixel index of top left pixel (assuming UVs are relative to top left corner of texture)
    vec2 pixCoord = uv.xy * colorTextureSize - 0.5f;    // First pixel goes from -0.5 to +0.4999 (0.0 is center) last pixel goes from (size - 1.5) to (size - 0.5000001)
    vec2 originPixCoord = floor(pixCoord);              // Pixel index coordinates of bottom left pixel of set of 4 we will be blending

    // For Gather we want UV coordinates of bottom right corner of top left pixel
    vec2 gUV = (originPixCoord + 1.0) / colorTextureSize;

    vec4 gIndex   = impl_textureGather(tex, gUV);

    vec4 c00   = texture(worldPalette, vec2(gIndex.w, 0.5));
    vec4 c01 = texture(worldPalette, vec2(gIndex.x, 0.5));
    vec4 c11  = texture(worldPalette, vec2(gIndex.y, 0.5));
    vec4 c10 = texture(worldPalette, vec2(gIndex.z, 0.5));

    if (blend_mode == D3DBLEND_SRCALPHA || blend_mode == D3DBLEND_INVSRCALPHA) {
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
    }

    vec2 filterWeight = pixCoord - originPixCoord;
 
    // Bi-linear mixing:
    vec4 temp0 = mix(c01, c11, filterWeight.x);
    vec4 temp1 = mix(c00, c10, filterWeight.x);
    vec4 blendColor = mix(temp1, temp0, filterWeight.y);

    return vec4(blendColor.r, blendColor.g, blendColor.b, blendColor.a);
}

vec4 bilinear_paletted_light(vec2 uv, float index)
{
    // Makes sure light is in a sane range
    float light = clamp(f_light, 0.0, 1.0);

    // Special case for lightsabers
    //if (index * 255.0 >= 16.0 && index * 255.0 < 17.0)
    //    light = 0.0;

    // Take the fragment light, and divide by 4.0 to select for colors
    // which glow in the dark
    float light_idx = light / LIGHT_DIVISOR;

    // Get texture size in pixels:
    vec2 colorTextureSize = vec2(textureSize(tex, 0));

    // Convert UV coordinates to pixel coordinates and get pixel index of top left pixel (assuming UVs are relative to top left corner of texture)
    vec2 pixCoord = uv.xy * colorTextureSize - 0.5f;    // First pixel goes from -0.5 to +0.4999 (0.0 is center) last pixel goes from (size - 1.5) to (size - 0.5000001)
    vec2 originPixCoord = floor(pixCoord);              // Pixel index coordinates of bottom left pixel of set of 4 we will be blending

    // For Gather we want UV coordinates of bottom right corner of top left pixel
    vec2 gUV = (originPixCoord + 1.0) / colorTextureSize;

    vec4 gIndex   = impl_textureGather(tex, gUV);

    vec4 c00   = texture(worldPalette, vec2(texture(worldPaletteLights, vec2(gIndex.w, light_idx)).r, 0.5));
    vec4 c01 = texture(worldPalette, vec2(texture(worldPaletteLights, vec2(gIndex.x, light_idx)).r, 0.5));
    vec4 c11  = texture(worldPalette, vec2(texture(worldPaletteLights, vec2(gIndex.y, light_idx)).r, 0.5));
    vec4 c10 = texture(worldPalette, vec2(texture(worldPaletteLights, vec2(gIndex.z, light_idx)).r, 0.5));

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
    vec4 light_mult_quad = vec4(light_mult, light_mult, light_mult, 1.0);

    return vec4(blendColor.r, blendColor.g, blendColor.b, 1.0) * light_mult_quad ;//* (1.0 - light) * light_mult;
}
#endif

void main(void)
{
    vec3 adj_texcoords = f_uv.xyz / f_uv.w;

    float originalZ = gl_FragCoord.z / gl_FragCoord.w;
#ifdef VIEW_SPACE_GBUFFER
    vec3 adjusted_coords = f_coord; // view space position
#else
    vec3 adjusted_coords = vec3(f_coord.x/iResolution.x, f_coord.y/iResolution.y, originalZ); // clip space pos
#endif
	vec3 adjusted_coords_norms = vec3(gl_FragCoord.x/iResolution.x, gl_FragCoord.y/iResolution.y, 1.0/gl_FragCoord.z);
    vec3 adjusted_coords_parallax = vec3(adjusted_coords_norms.x - 0.5, adjusted_coords_norms.y - 0.5, gl_FragCoord.z);
    vec3 face_normals = normals(adjusted_coords_norms);
    vec3 face_normals_parallax = normals(adjusted_coords_parallax);

    if(displacement_factor != 0.0)
	{
        adj_texcoords.xy = parallax_mapping(f_uv.xy, face_normals_parallax, adjusted_coords_parallax);
    }
	else if(uv_mode == 0)
	{
		adj_texcoords.xy = f_uv_affine;
	}

    vec4 sampled = texture(tex, adj_texcoords.xy);
    vec4 sampledEmiss = texture(texEmiss, adj_texcoords.xy);
    vec4 sampled_color = vec4(1.0, 1.0, 1.0, 1.0);
    vec4 vertex_color = f_color;
    float index = sampled.r;
    vec4 palval = texture(worldPalette, vec2(index, 0.5));
    vec4 color_add = vec4(0.0, 0.0, 0.0, 1.0);
    vec4 color_add_emiss = vec4(0.0, 0.0, 0.0, 0.0);
	vec4 emissive = vec4(0.0);

	vec3 surfaceNormals = normalize(f_normal);

    if (tex_mode == TEX_MODE_TEST) {
		sampled_color = fillColor;
    }
    else if (tex_mode == TEX_MODE_16BPP
    || tex_mode == TEX_MODE_BILINEAR_16BPP
    )
    {
        sampled_color = vec4(sampled.b, sampled.g, sampled.r, sampled.a);
    }
    else if (tex_mode == TEX_MODE_WORLDPAL
#ifndef CAN_BILINEAR_FILTER
    || tex_mode == TEX_MODE_BILINEAR
#endif
    )

    {
        if (index == 0.0 && (blend_mode == D3DBLEND_SRCALPHA || blend_mode == D3DBLEND_INVSRCALPHA))
            discard;

        // Makes sure light is in a sane range
        float light = clamp(f_light, 0.0, 1.0);

        // Special case for lightsabers
        //if (index * 255.0 >= 16.0 && index * 255.0 < 17.0)
        //    light = 0.0;

        // Take the fragment light, and divide by 4.0 to select for colors
        // which glow in the dark
        float light_idx = light / LIGHT_DIVISOR;

        // Get the shaded palette index
        float light_worldpalidx = texture(worldPaletteLights, vec2(index, light_idx)).r;

        // Now take our index and look up the corresponding palette value
        vec4 lightPalval = texture(worldPalette, vec2(light_worldpalidx, 0.5));

		emissive = lightPalval;
        color_add = lightPalval;
        sampled_color = palval;
    }
#ifdef CAN_BILINEAR_FILTER
    else if (tex_mode == TEX_MODE_BILINEAR)
    {
        sampled_color = bilinear_paletted(adj_texcoords.xy);
        color_add = bilinear_paletted_light(adj_texcoords.xy, index);
		emissive = color_add / light_mult;
        if (sampled_color.a < 0.01) {
            discard;
        }
    }
#endif

    vec4 albedoFactor_copy = albedoFactor;

    if (blend_mode == D3DBLEND_INVSRCALPHA)
    {
        if (vertex_color.a < 0.01) {
            discard;
        }
        //albedoFactor_copy.a = (1.0 - albedoFactor_copy.a);
        //vertex_color.a = (1.0 - vertex_color.a);
        //sampled_color.a = (1.0 - sampled_color.a);
    }

    if (blend_mode != D3DBLEND_SRCALPHA && blend_mode != D3DBLEND_INVSRCALPHA && vertex_color.a != 0.0)
    {
        vertex_color.a = 1.0;
    }

	vec3 localViewDir = normalize(-f_coord.xyz);
	vec3 reflVec = reflect(-localViewDir, surfaceNormals);

	vec3 diffuseColor = sampled_color.xyz;
	vec3 specularColor = vec3(0.0);//min(diffuseColor.xyz, fillColor.xyz);
	float roughness = 0.1;	
	//float gloss = 1.0 - roughness;
	float shiny = 8.0;

	if(lightMode == 4)
	{
		// for specular materials, try to split the texture highlights and shadows around the fill color
		//diffuseColor = min(sampled_color.xyz, fillColor.xyz);
		//specularColor = max(sampled_color.xyz, fillColor.xyz);

		diffuseColor = vec3(0.0);//min(sampled_color.xyz, fillColor.xyz); // poor woman's highlight removal
		specularColor = sampled_color.xyz;
	}

	vec3 diffuseLight = vertex_color.xyz;
	vec3 specLight = vec3(0.0);

	if(lightMode == 0) // full lit
	{
		diffuseLight.xyz = vec3(1.0);
	}
	else if(lightMode == 1) // not lit
	{
		diffuseLight.xyz = vec3(0.0);
	}
	else if(lightMode >= 2)
	{
		if (ambientMode == 1)
		{
			// original JK behavior seems to be max()
			diffuseLight.xyz = max(diffuseLight.xyz, ambientColor.xyz);
		}
		else if (ambientMode == 2)
		{
			if(lightMode == 4)
				specLight.xyz += CalculateAmbientSpecular(surfaceNormals, localViewDir, roughness);
			else
				diffuseLight.xyz += CalculateAmbientDiffuse(surfaceNormals);
		}

		// https://seblagarde.wordpress.com/2012/06/03/spherical-gaussien-approximation-for-blinn-phong-phong-and-fresnel/
		// Point lights using SG approximations for consistency
		#define LN2DIV8               0.08664
		#define Log2Of1OnLn2_Plus1    1.528766
		float ModifiedSpecularPower = 1.0 / log(2) * shiny;// * (2.0 / roughness - 2);//exp2(10.0 * gloss + Log2Of1OnLn2_Plus1);

		vec4 R2 = vec4(ModifiedSpecularPower * reflVec, -ModifiedSpecularPower);

		float scalar = 0.4; // todo: needs to come from rdCamera_pCurCamera->attenuationMin
		int totalLights = min(numLights, 128);
		for(int lt = 0; lt < totalLights; ++lt)
		{
			light l = lights[lt];
			if(l.isActive == 0u)
				continue;

			vec3 diff = l.position.xyz - f_coord.xyz;
			float len;
			if (lightMode == 2) // diffuse uses dist to plane
				len = dot(l.position.xyz - f_coord.xyz, surfaceNormals.xyz);
			else
				len = length(diff);

			if ( len < l.falloffMin )
			{
				diff = normalize(diff);
				float lightMagnitude = dot(surfaceNormals, diff);
				if (lightMode > 2)
					lightMagnitude = do_half_lambert(lightMagnitude);

				if ( lightMagnitude > 0.0 )
				{
					float intensity = max(0.0, l.direction_intensity.w - len * scalar) * lightMagnitude;
					if(lightMode == 4)
						specLight.xyz += intensity * l.color.xyz * exp2(dot(R2, vec4(diff, 1.0)));
					else			
						diffuseLight.xyz += intensity * l.color.xyz;
				}
			}
		}
		specLight *= (LN2DIV8 * ModifiedSpecularPower + 0.25);
	}

    vec4 main_color = vec4(diffuseColor.xyz * diffuseLight.xyz + specularColor.xyz * specLight.xyz, vertex_color.a);
	main_color.rgb = max(main_color.rgb, emissive.rgb);

#ifdef GPU_LIGHTING
	//color_add_emiss.xyz += max(vec3(0.0), main_color.xyz - 1.0);
#endif

    vec4 effectAdd_color = vec4(colorEffects_add.r, colorEffects_add.g, colorEffects_add.b, 0.0);
    
    main_color *= albedoFactor_copy;
    float should_write_normals = 1.0;
    float orig_alpha = main_color.a;

    if (main_color.a < 0.01 && sampledEmiss.r == 0.0 && sampledEmiss.g == 0.0 && sampledEmiss.b == 0.0) {
        discard;
    }
    
    if (blend_mode == D3DBLEND_INVSRCALPHA)
    {
        main_color.rgb *= (1.0 - main_color.a);
        main_color.a = (1.0 - main_color.a);
    }

    //if (blend_mode == D3DBLEND_SRCALPHA || blend_mode == D3DBLEND_INVSRCALPHA)
    {
        should_write_normals = main_color.a > 0.5 ? 1.0 : 0.0;
    }

    //if (sampledEmiss.r != 0.0 || sampledEmiss.g != 0.0 || sampledEmiss.b != 0.0)
    {
        color_add.rgb += sampledEmiss.rgb * emissiveFactor * 0.1;
    }

    if (sampledEmiss.r != 0.0 || sampledEmiss.g != 0.0 || sampledEmiss.b != 0.0)
    {
        color_add_emiss.rgb += sampledEmiss.rgb * 0.1;
    }
	
#ifdef FOG
	if(fogEnabled > 0)
	{
		float fog_amount = clamp((originalZ - fogStart) / (fogEnd - fogStart), 0.0, 1.0);
		fog_amount *= fogColor.a;

		main_color.rgb = mix(main_color.rgb, fogColor.rgb, fog_amount);
		color_add.rgb = mix(color_add.rgb, fogColor.rgb, fog_amount);
	}
	#endif

    fragColor = main_color + effectAdd_color;// + color_add;

	// dither the output in case we're using some lower precision output
	if(enableDither > 0)
	{
		const float DITHER_LUT[16] = float[16](
				0, 4, 1, 5,
				6, 2, 7, 3,
				1, 5, 0, 4,
				7, 3, 6, 2
		);	

		int wrap_x = int(gl_FragCoord.x) & 3;
		int wrap_y = int(gl_FragCoord.y) & 3;
		int wrap_index = wrap_x + wrap_y * 4;
		fragColor.rgb = min(fragColor.rgb + DITHER_LUT[wrap_index] / 255.0, vec3(1.0));
	}

    color_add.a = orig_alpha;

    float luma = luminance(color_add.rgb) * 0.5;// * 4.0;

    if (emissiveFactor.r != 0.0 || emissiveFactor.g != 0.0 || emissiveFactor.b != 0.0)
    {
        //color_add = vec4(1.0, 1.0, 1.0, 1.0);
        luma = 1.0;
    }

    vec3 tint = normalize(colorEffects_tint + 1.0) * sqrt(3.0);

    color_add.r *= tint.r;
    color_add.g *= tint.g;
    color_add.b *= tint.b;

    color_add.r *= colorEffects_fade;
    color_add.g *= colorEffects_fade;
    color_add.b *= colorEffects_fade;

    color_add.r *= colorEffects_filter.r;
    color_add.g *= colorEffects_filter.g;
    color_add.b *= colorEffects_filter.b;

    //color_add = vec4(0.0, 0.0, 0.0, 1.0);

    // Dont include any windows or transparent objects in emissivity output
    if (luma < 0.01 && orig_alpha < 0.5 && (blend_mode == D3DBLEND_SRCALPHA || blend_mode == 6))
    {
        color_add = vec4(0.0, 0.0, 0.0, 0.0);
    }

    fragColorEmiss = color_add_emiss + color_add;

    //fragColor = vec4(face_normals_parallax.x, face_normals_parallax.y, face_normals_parallax.z, 1.0);
    //fragColor = vec4(face_normals*0.5 + 0.5,1.0);
    //vec4 test_norms = (main_color + effectAdd_color);
    //test_norms.xyz *= dot(vec3(1.0, 0.0, -0.7), face_normals);
    //fragColor = test_norms;

	// output linear depth
	fragColorDepth = f_depth;

	// octahedron encoded normal
	vec2 octaNormal = encode_octahedron(surfaceNormals);
    fragColorNormal = octaNormal.xy;

	// unlit diffuse color for deferred lights and decals
	fragColorDiffuse = sampled_color;
}
