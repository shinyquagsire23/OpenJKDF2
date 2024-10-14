#ifdef GL_ARB_texture_query_lod
float impl_textureQueryLod(sampler2D tex, vec2 uv)
{
	return textureQueryLOD(tex, uv).x;
}
#else
float impl_textureQueryLod(sampler2D tex, vec2 uv)
{
    vec2 dims = textureSize(tex, 0);
	vec2  texture_coordinate = uv * dims;
    vec2  dx_vtc        = dFdx(texture_coordinate);
    vec2  dy_vtc        = dFdy(texture_coordinate);
    float delta_max_sqr = max(dot(dx_vtc, dx_vtc), dot(dy_vtc, dy_vtc));
    float mml = 0.5 * log2(delta_max_sqr);
    return max( 0, mml );
}
#endif

#define TEX_MODE_TEST 0
#define TEX_MODE_WORLDPAL 1
#define TEX_MODE_BILINEAR 2
#define TEX_MODE_16BPP 5
#define TEX_MODE_BILINEAR_16BPP 6

uniform sampler2D tex;
uniform sampler2D texEmiss;
uniform sampler2D worldPalette;
uniform sampler2D worldPaletteLights;
uniform sampler2D displacement_map;

uniform int tex_mode;
uniform int blend_mode;
uniform vec3 emissiveFactor;
uniform vec4 albedoFactor;
uniform float displacement_factor;

in vec4 f_color;
in float f_light;
in vec4 f_uv;
in vec3 f_coord;
in vec3 f_normal;
in float f_depth;

noperspective in vec2 f_uv_affine;

uniform sharedBlock
{
	vec4  ambientSGBasis[8];

	vec4  colorEffects_tint;
	vec4  colorEffects_filter;
	vec4  colorEffects_add;
	
	vec4  mipDistances;

	float colorEffects_fade;
	float light_mult;
	uint  pad0;
	uint  pad1;

	vec2  clusterTileSizes;
	vec2  clusterScaleBias;

	vec2  iResolution;
	uint  firstLight;
	uint  numLights;

	uint  firstOccluder;
	uint  numOccluders;
	uint  firstDecal;
	uint  numDecals;
};

uniform mat4 modelMatrix;
uniform mat4 projMatrix;

uniform int uv_mode;
uniform vec4 fillColor;
uniform int numMips;

uint compute_mip_lod(float z_min)
{
	uint mipmap_level = 0;
	mipmap_level = z_min < mipDistances.x ? mipmap_level : 1;
	mipmap_level = z_min < mipDistances.y ? mipmap_level : 2;
	mipmap_level = z_min < mipDistances.z ? mipmap_level : 3;
	return mipmap_level;
}

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
	float mip = impl_textureQueryLod(tex, uv);
	mip += float(compute_mip_lod(f_coord.y));
	mip = min(mip, float(numMips - 1));

	ivec2 ires = textureSize( tex, int(mip) );
	vec2  fres = vec2( ires );

	vec2 st = uv*fres - 0.5;
    vec2 i = floor( st );
    vec2 w = fract( st );

	// textureGather doesn't handle mips, need to sample manually
	// use textureLod instead of texelFetch/manual textureGather to respect sampler states
	// this should be quite cache friendly so the overhead is minimal
    float a = textureLod( tex, (i + vec2(0.5,0.5)) / fres, mip ).x;
    float b = textureLod( tex, (i + vec2(1.5,0.5)) / fres, mip ).x;
    float c = textureLod( tex, (i + vec2(0.5,1.5)) / fres, mip ).x;
    float d = textureLod( tex, (i + vec2(1.5,1.5)) / fres, mip ).x;
	
	// read the palette
	vec4 ca = texture(worldPalette, vec2(a, 0.5));
    vec4 cb = texture(worldPalette, vec2(b, 0.5));
    vec4 cc = texture(worldPalette, vec2(c, 0.5));
    vec4 cd = texture(worldPalette, vec2(d, 0.5));

	//if (blend_mode == D3DBLEND_SRCALPHA || blend_mode == D3DBLEND_INVSRCALPHA)
	{
        if (a == 0.0) {
            ca.a = 0.0;
        }
        if (b == 0.0) {
            cb.a = 0.0;
        }
        if (c == 0.0) {
            cc.a = 0.0;
        }
        if (d == 0.0) {
            cd.a = 0.0;
        }
    }

	return mix(mix(ca, cb, w.x), mix(cc, cd, w.x), w.y);
}
#endif

void main(void)
{
#ifdef ALPHA_DISCARD
    vec3 adj_texcoords = f_uv.xyz / f_uv.w;

    float originalZ = gl_FragCoord.z / gl_FragCoord.w;
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

	// software actually uses the zmin of the entire face
	float mipBias = float(compute_mip_lod(f_coord.y));
	mipBias = min(mipBias, float(numMips - 1));

    vec4 sampled = texture(tex, adj_texcoords.xy, mipBias);
    
	vec4 sampled_color = vec4(1.0, 1.0, 1.0, 1.0);
    vec4 vertex_color = f_color;
    float index = sampled.r;
    vec4 palval = texture(worldPalette, vec2(index, 0.5));
  
    if (tex_mode == TEX_MODE_TEST)
	{
		sampled_color = fillColor;
    }
    else if (tex_mode == TEX_MODE_16BPP || tex_mode == TEX_MODE_BILINEAR_16BPP)
    {
        sampled_color = vec4(sampled.b, sampled.g, sampled.r, sampled.a);
    }
    else if (tex_mode == TEX_MODE_WORLDPAL
#ifndef CAN_BILINEAR_FILTER
		|| tex_mode == TEX_MODE_BILINEAR
#endif
    )
    {
        if (index == 0.0) // todo: alpha ref/chroma key
            discard;

        vec4 lightPalval = texture(worldPalette, vec2(index, 0.5));
        sampled_color = palval;
    }
#ifdef CAN_BILINEAR_FILTER
    else if (tex_mode == TEX_MODE_BILINEAR)
    {
        sampled_color = bilinear_paletted(adj_texcoords.xy);
    }
#endif

	if (sampled_color.a < 0.01)
		discard;

	// if we want to output some thin gbuffer
	//fragColorDepth = f_depth;
    //fragColorNormal = encode_octahedron(f_normal);
	//fragColorDiffuse = sampled_color;

#endif
}
