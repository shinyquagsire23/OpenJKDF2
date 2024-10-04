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

uniform usamplerBuffer clusterBuffer;

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
uniform mat4 mvp;

uniform int uv_mode;
uniform vec4 fillColor;

// fixme: specular mode is currently a metal mode, where metalness is assumed to be 1.0 with 0 diffuse component
// this is pretty limiting atm, I'd like to get some shiny storm troopers but their armor is more like plastic
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

struct occluder
{
	vec4 position;
};

uniform int numOccluders;
uniform occluderBlock
{
	occluder occluders[128];
};

// todo: define outside
#define CLUSTER_MAX_LIGHTS          128u
#define CLUSTER_MAX_OCCLUDERS       128u
#define CLUSTER_MAX_ITEMS           (CLUSTER_MAX_LIGHTS + CLUSTER_MAX_OCCLUDERS)
#define CLUSTER_BUCKETS_PER_CLUSTER (CLUSTER_MAX_ITEMS / 32u)
#define CLUSTER_GRID_SIZE_X         16u
#define CLUSTER_GRID_SIZE_Y         8u
#define CLUSTER_GRID_SIZE_Z         24u
#define CLUSTER_GRID_SIZE_XYZ (CLUSTER_GRID_SIZE_X * CLUSTER_GRID_SIZE_Y * CLUSTER_GRID_SIZE_Z)
#define CLUSTER_GRID_TOTAL_SIZE (CLUSTER_GRID_SIZE_X * CLUSTER_GRID_SIZE_Y * CLUSTER_GRID_SIZE_Z * CLUSTER_BUCKETS_PER_CLUSTER)

uniform vec2 clusterScaleBias;
uniform vec2 clusterTileSizes;

uint get_cluster_z_index(float screen_depth)
{
	return uint(max(log(screen_depth) * clusterScaleBias.x + clusterScaleBias.y, 0.0));
}

uint compute_cluster_index(vec2 pixel_pos, float screen_depth)
{
	uint z_index = get_cluster_z_index(screen_depth);
    uvec3 indices = uvec3(uvec2(pixel_pos.xy / clusterTileSizes.xy), z_index);
    uint cluster = indices.x + indices.y * CLUSTER_GRID_SIZE_X + indices.z * CLUSTER_GRID_SIZE_X * CLUSTER_GRID_SIZE_Y;
    return cluster;
}

// not available in GL < 4.0
// pretty naive approach, can do better
int findLSB(uint x)
{
	int res = -1;
	for (uint i = 0u; i < 32u; i++)
	{
		uint mask = 1u << i;
		if ((x & mask) == mask)
		{
			res = int(i);
			break;
		}
	}
	return res;
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

// debug view
vec3 temperature(float t)
{
    vec3 c[10] = vec3[10](
        vec3(   0.0/255.0,   2.0/255.0,  91.0f/255.0 ),
        vec3(   0.0/255.0, 108.0/255.0, 251.0f/255.0 ),
        vec3(   0.0/255.0, 221.0/255.0, 221.0f/255.0 ),
        vec3(  51.0/255.0, 221.0/255.0,   0.0f/255.0 ),
        vec3( 255.0/255.0, 252.0/255.0,   0.0f/255.0 ),
        vec3( 255.0/255.0, 180.0/255.0,   0.0f/255.0 ),
        vec3( 255.0/255.0, 104.0/255.0,   0.0f/255.0 ),
        vec3( 226.0/255.0,  22.0/255.0,   0.0f/255.0 ),
        vec3( 191.0/255.0,   0.0/255.0,  83.0f/255.0 ),
        vec3( 145.0/255.0,   0.0/255.0,  65.0f/255.0 ) 
    );

    float s = t * 10.0;

    int cur = int(s) <= 9 ? int(s) : 9;
    int prv = cur >= 1 ? cur - 1 : 0;
    int nxt = cur < 9 ? cur + 1 : 9;

    float blur = 0.8;

    float wc = smoothstep( float(cur) - blur, float(cur) + blur, s ) * (1.0 - smoothstep(float(cur + 1) - blur, float(cur + 1) + blur, s) );
    float wp = 1.0 - smoothstep( float(cur) - blur, float(cur) + blur, s );
    float wn = smoothstep( float(cur + 1) - blur, float(cur + 1) + blur, s );

    vec3 r = wc * c[cur] + wp * c[prv] + wn * c[nxt];
    return vec3( clamp(r.x, 0.0f, 1.0), clamp(r.y, 0.0, 1.0), clamp(r.z, 0.0, 1.0) );
}


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
    return max(SGInnerProduct(lightingLobe, cosineLobe), 0.0);
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
		//spec *= specColor + (1.0 - specColor) * pow((1.0 - clamp(dot(warpedNDF.Axis, h), 0.0, 1.0)), 5.0);
		
		spec *= nDotL;
		ambientSpecular.xyz += spec / 3.141592;
	}
	return ambientSpecular;
}

float HalfLambert(float ndotl)
{
	ndotl = ndotl * 0.5 + 0.5;
	return ndotl * ndotl;
}

void CalculatePointLighting(uint bucket_index, vec3 normal, vec3 view, inout vec3 diffuseLight, inout vec3 specLight)
{
	// https://seblagarde.wordpress.com/2012/06/03/spherical-gaussien-approximation-for-blinn-phong-phong-and-fresnel/
	// Point lights using SG approximations for consistency and a little speed
	#define LN2DIV8               0.08664
	#define Log2Of1OnLn2_Plus1    1.528766
	float ModifiedSpecularPower = 1.0 / log(2.0) * 8.0;// * (2.0 / roughness - 2);//exp2(10.0 * gloss + Log2Of1OnLn2_Plus1);

	vec3 reflVec = reflect(-view, normal);
	vec4 R2 = vec4(ModifiedSpecularPower * reflVec, -ModifiedSpecularPower);
	float specNormalization = (LN2DIV8 * ModifiedSpecularPower + 0.25);

	float scalar = 0.4; // todo: needs to come from rdCamera_pCurCamera->attenuationMin

	// debug
	//float lightOverdraw = 0.0;
	//int totalLights = min(numLights, 128);
	//for(int light_index = 0; light_index < totalLights; ++light_index)

	uint first_item = 0u;
	uint last_item = first_item + uint(numLights) - 1u;
	uint first_bucket = first_item / 32u;
	uint last_bucket = min(last_item / 32u, max(0u, CLUSTER_BUCKETS_PER_CLUSTER - 1u));
	for (uint bucket = first_bucket; bucket <= last_bucket; ++bucket)
	{
		uint bucket_bits = uint(texelFetch(clusterBuffer, int(bucket_index + bucket)).x);
		while(bucket_bits != 0u)
		{
			uint bucket_bit_index = uint(findLSB(bucket_bits));
			uint light_index = bucket * 32u + bucket_bit_index;
			bucket_bits ^= uint(1 << bucket_bit_index);
				
			if (light_index >= first_item && light_index <= last_item)
			{
				//lightOverdraw += 1.0;

				light l = lights[light_index];

				vec3 diff = l.position.xyz - f_coord.xyz;
				float len;
				if (lightMode == 2) // diffuse uses dist to plane
					len = dot(l.position.xyz - f_coord.xyz, normal.xyz);
				else
					len = length(diff);

				// todo: how much branching do we really want to do here?
				if ( len < l.falloffMin )
				{
					diff = normalize(diff);
					float lightMagnitude = dot(normal, diff);
					//if (lightMode > 2) // gouraud and higher use half lambert
						//lightMagnitude = HalfLambert(lightMagnitude);
					lightMagnitude = max(lightMagnitude, 0.0);

					if ( lightMagnitude > 0.0 )
					{
						// this is JK's attenuation model, note it depends heavily on scalar being correct
						float intensity = max(0.0, l.direction_intensity.w - len * scalar) * lightMagnitude;
						//float intensity = max(0.0, (l.falloffMin - len) / l.falloffMin) * l.direction_intensity.w;
						if(lightMode == 4)
							specLight.xyz += intensity * l.color.xyz * exp2(dot(R2, vec4(diff, 1.0))) * specNormalization;
						else			
							diffuseLight.xyz += intensity * l.color.xyz;
					}
				}
			}
		}
	}

	//specLight *= 0;

	//uint z_index = get_cluster_z_index(f_depth);
	//diffuseLight = temperature(lightOverdraw / 32.0);
}

vec3 CalculateIndirectShadows(uint bucket_index, vec3 pos, vec3 normal)
{
	float shadowing = 1.0;
	//float overDraw = 0.0;

	uint first_item = CLUSTER_MAX_LIGHTS;
	uint last_item = first_item + uint(numOccluders) - 1u;
	uint first_bucket = first_item / 32u;
	uint last_bucket = min(last_item / 32u, max(0u, CLUSTER_BUCKETS_PER_CLUSTER - 1u));
	for (uint bucket = first_bucket; bucket <= last_bucket; ++bucket)
	//for (int occluder_index = 0; occluder_index < numOccluders; ++occluder_index)
	{
		uint bucket_bits = uint(texelFetch(clusterBuffer, int(bucket_index + bucket)).x);
		while(bucket_bits != 0u)
		{
			uint bucket_bit_index = uint(findLSB(bucket_bits));
			uint occluder_index = bucket * 32u + bucket_bit_index;
			bucket_bits ^= uint(1 << bucket_bit_index);
			
			if (occluder_index >= first_item && occluder_index <= last_item && shadowing > 5.0 / 255.0)
			{
				//overDraw += 1.0;				
				//occluder occ = occluders[occluder_index];

				occluder occ = occluders[occluder_index - first_item];

				vec3 direction = (occ.position.xyz - pos.xyz);
				float len = length(occ.position.xyz - pos.xyz);
				if (len < occ.position.w)
				{
					float rcpLen = 1.0 / max(len, 0.0001);
					direction *= rcpLen;

					float cosTheta = dot(normal, direction);
					if(cosTheta > 0.0)
					{
						float solidAngle = (1.0 - cos(atanFast(occ.position.w * rcpLen)));

						// simplified smoothstep falloff, equivalent to smoothstep(0, occ.position.w, occ.position.w - len)
						float falloff = clamp((occ.position.w - len) / occ.position.w, 0.0, 1.0);
						//falloff = falloff * falloff * (3.0 - 2.0 * falloff); the smoothstep part doesn't seem too important

						float integralSolidAngle = cosTheta * solidAngle * falloff;
						shadowing *= 1.0 - integralSolidAngle;



					}
				}
			}
		}
	}

	return vec3(shadowing);
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

	// todo: make sure all the jkgm stuff still works
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
#ifdef ALPHA_DISCARD
        if (index == 0.0)// && (blend_mode == D3DBLEND_SRCALPHA || blend_mode == D3DBLEND_INVSRCALPHA))
            discard;
#endif

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
	#ifdef ALPHA_DISCARD
        if (sampled_color.a < 0.01) {
            discard;
        }
	#endif
    }
#endif

    vec4 albedoFactor_copy = albedoFactor;

    if (blend_mode == D3DBLEND_INVSRCALPHA)
    {
	#ifdef ALPHA_DISCARD
        if (vertex_color.a < 0.01) {
            discard;
        }
	#endif
        //albedoFactor_copy.a = (1.0 - albedoFactor_copy.a);
        //vertex_color.a = (1.0 - vertex_color.a);
        //sampled_color.a = (1.0 - sampled_color.a);
    }

    if (blend_mode != D3DBLEND_SRCALPHA && blend_mode != D3DBLEND_INVSRCALPHA && vertex_color.a != 0.0)
    {
        vertex_color.a = 1.0;
    }

	vec3 localViewDir = normalize(-f_coord.xyz);
	uint cluster_index = compute_cluster_index(gl_FragCoord.xy, f_coord.y);
	uint bucket_index = cluster_index * CLUSTER_BUCKETS_PER_CLUSTER;

	vec3 diffuseColor = sampled_color.xyz;
	vec3 specularColor = vec3(0.0);//min(diffuseColor.xyz, fillColor.xyz);
	float roughness = 0.01;	

	if(lightMode == 4)
	{
		// for specular materials, try to split the texture highlights and shadows around the fill color
		//diffuseColor = min(sampled_color.xyz, fillColor.xyz);
		//specularColor = max(sampled_color.xyz, fillColor.xyz);

		//diffuseColor = vec3(0.0);//min(sampled_color.xyz, fillColor.xyz); // poor woman's highlight removal
		specularColor = sampled_color.xyz;//fillColor.xyz;// sampled_color.xyz;
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
		if (ambientMode > 0)
		{
			// original JK behavior seems to be max()
			diffuseLight.xyz = max(diffuseLight.xyz, ambientColor.xyz);
		}

		if (ambientMode == 2)
		{
			//diffuseLight.xyz += CalculateAmbientDiffuse(surfaceNormals);
			if(lightMode == 4)
				specLight.xyz += CalculateAmbientSpecular(surfaceNormals, localViewDir, roughness);
			else
				diffuseLight.xyz += CalculateAmbientDiffuse(surfaceNormals);
		}
		
		if (numLights > 0)
			CalculatePointLighting(bucket_index, surfaceNormals, localViewDir, diffuseLight, specLight);
			
		//diffuseColor.xyz = vec3(1.0);

		if (numOccluders > 0)
		{
			vec3 shadows = CalculateIndirectShadows(bucket_index, f_coord.xyz, surfaceNormals);	
			diffuseLight.xyz *= shadows;
			specLight.xyz *= shadows;
		}
	}

	// todo: maybe tone map this?
	diffuseLight = clamp(diffuseLight.xyz, vec3(0.0), vec3(1.0));	
	specLight = clamp(specLight.xyz, vec3(0.0), vec3(1.0));

    vec4 main_color = vec4(diffuseColor.xyz * diffuseLight.xyz + specularColor.xyz * specLight.xyz, vertex_color.a);
	main_color.rgb = max(main_color.rgb, emissive.rgb);

#ifdef GPU_LIGHTING
	//color_add_emiss.xyz += max(vec3(0.0), main_color.xyz - 1.0);
#endif

    vec4 effectAdd_color = vec4(colorEffects_add.r, colorEffects_add.g, colorEffects_add.b, 0.0);
    
    main_color *= albedoFactor_copy;
    float should_write_normals = 1.0;
    float orig_alpha = main_color.a;

#ifdef ALPHA_DISCARD
    if (main_color.a < 0.01 && sampledEmiss.r == 0.0 && sampledEmiss.g == 0.0 && sampledEmiss.b == 0.0) {
        discard;
    }
#endif
    
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
