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

#ifdef CLASSIC_EMISSIVE
#define LIGHT_DIVISOR (3.0)
#else
#define LIGHT_DIVISOR (6.0)
#endif
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

#ifdef FOG
uniform int fogEnabled;
uniform vec4 fogColor;
uniform float fogStart;
uniform float fogEnd;
#endif

in vec4 f_color;
in float f_light;
in vec2 f_uv;
in vec3 f_coord;

layout(location = 0) out vec4 fragColor;
layout(location = 1) out vec4 fragColorEmiss;
layout(location = 2) out vec4 fragColorPos;
layout(location = 3) out vec4 fragColorNormal;
#ifdef DECAL_RENDERING
layout(location = 4) out vec4 fragColorLight;

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
    return clamp(v.xy, vec2(-1.0), vec2(1.0));
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

mat3 construct_tbn(vec3 vp_normal, vec3 adjusted_coords)
{
    vec3 n = normalize(vp_normal);

    vec3 dp1 = dFdx(adjusted_coords);
    vec3 dp2 = dFdy(adjusted_coords);
    vec2 duv1 = dFdx(f_uv);
    vec2 duv2 = dFdy(f_uv);

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
    vec3 view_dir = -normalize(transpose(construct_tbn(vp_normal, adjusted_coords)) * adjusted_coords);

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
vec4 bilinear_paletted()
{
    // Get texture size in pixels:
    vec2 colorTextureSize = vec2(textureSize(tex, 0));

    // Convert UV coordinates to pixel coordinates and get pixel index of top left pixel (assuming UVs are relative to top left corner of texture)
    vec2 pixCoord = f_uv * colorTextureSize - 0.5f;    // First pixel goes from -0.5 to +0.4999 (0.0 is center) last pixel goes from (size - 1.5) to (size - 0.5000001)
    vec2 originPixCoord = floor(pixCoord);              // Pixel index coordinates of bottom left pixel of set of 4 we will be blending

    // For Gather we want UV coordinates of bottom right corner of top left pixel
    vec2 gUV = (originPixCoord + 1.0f) / colorTextureSize;

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

vec4 bilinear_paletted_light(float index)
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
    vec2 pixCoord = f_uv * colorTextureSize - 0.5f;    // First pixel goes from -0.5 to +0.4999 (0.0 is center) last pixel goes from (size - 1.5) to (size - 0.5000001)
    vec2 originPixCoord = floor(pixCoord);              // Pixel index coordinates of bottom left pixel of set of 4 we will be blending

    // For Gather we want UV coordinates of bottom right corner of top left pixel
    vec2 gUV = (originPixCoord + 1.0f) / colorTextureSize;

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
    float originalZ = gl_FragCoord.z / gl_FragCoord.w;
#ifdef DECAL_RENDERING
    vec3 adjusted_coords = f_coord; // view space position
#else
    vec3 adjusted_coords = vec3(f_coord.x/iResolution.x, f_coord.y/iResolution.y, originalZ); // clip space pos
#endif
	vec3 adjusted_coords_norms = vec3(gl_FragCoord.x/iResolution.x, gl_FragCoord.y/iResolution.y, 1.0/gl_FragCoord.z);
    vec3 adjusted_coords_parallax = vec3(adjusted_coords_norms.x - 0.5, adjusted_coords_norms.y - 0.5, gl_FragCoord.z);
    vec3 face_normals = normals(adjusted_coords_norms);
    vec3 face_normals_parallax = normals(adjusted_coords_parallax);

    vec2 adj_texcoords = f_uv;
    if(displacement_factor != 0.0) {
        adj_texcoords = parallax_mapping(f_uv, face_normals_parallax, adjusted_coords_parallax);
    }

    vec4 sampled = texture(tex, adj_texcoords);
    vec4 sampledEmiss = texture(texEmiss, adj_texcoords);
    vec4 sampled_color = vec4(1.0, 1.0, 1.0, 1.0);
    vec4 vertex_color = f_color;
    float index = sampled.r;
    vec4 palval = texture(worldPalette, vec2(index, 0.5));
    vec4 color_add = vec4(0.0, 0.0, 0.0, 1.0);
    vec4 color_add_emiss = vec4(0.0, 0.0, 0.0, 0.0);
#ifdef CLASSIC_EMISSIVE
	vec4 emissive = vec4(0.0);
#endif

    if (tex_mode == TEX_MODE_TEST) {
        sampled_color = vec4(1.0, 1.0, 1.0, 1.0);
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

	#ifdef CLASSIC_EMISSIVE	
		emissive = lightPalval;
	#endif
        // Add more of the emissive color depending on the darkness of the fragment
        color_add = (lightPalval  * light_mult); // * (1.0 - light)
        sampled_color = palval;
    }
#ifdef CAN_BILINEAR_FILTER
    else if (tex_mode == TEX_MODE_BILINEAR)
    {
        sampled_color = bilinear_paletted();
        color_add = bilinear_paletted_light(index);
	#ifdef CLASSIC_EMISSIVE	
		emissive = color_add / light_mult;
	#endif
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

    vec4 main_color = (sampled_color * vertex_color);
#ifdef CLASSIC_EMISSIVE
	main_color.rgb = max(main_color.rgb, emissive.rgb);
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

    color_add.a = orig_alpha;

    float luma = luminance(color_add.rgb) * 0.5;// * 4.0;

    if (emissiveFactor.r != 0.0 || emissiveFactor.g != 0.0 || emissiveFactor.b != 0.0)
    {
        //color_add = vec4(1.0, 1.0, 1.0, 1.0);
        luma = 1.0;
    }
    else
    {
        // The emissive maps also include slight amounts of darkly-rendered geometry,
        // so we want to ramp the amount that gets added based on luminance/brightness.
        

        color_add.r *= luma;
        color_add.g *= luma;
        color_add.b *= luma;
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

    if (blend_mode == D3DBLEND_INVSRCALPHA) {
        //color_add.a = (1.0 - color_add.a);
        //should_write_normals = 1.0 - should_write_normals;
    }

    fragColorEmiss = color_add_emiss + color_add;

    //fragColor = vec4(face_normals_parallax.x, face_normals_parallax.y, face_normals_parallax.z, 1.0);
    //fragColor = vec4(face_normals*0.5 + 0.5,1.0);
    //vec4 test_norms = (main_color + effectAdd_color);
    //test_norms.xyz *= dot(vec3(1.0, 0.0, -0.7), face_normals);
    //fragColor = test_norms;

	gl_FragDepth = gl_FragCoord.z;
    fragColorPos = vec4(adjusted_coords.x, adjusted_coords.y, adjusted_coords.z, should_write_normals);
#ifdef DECAL_RENDERING
	vec2 octaNormal = encode_octahedron(normals(adjusted_coords.xyz)); // encode normal so we can store depth in Z
    fragColorNormal = vec4(octaNormal.xy, originalZ, should_write_normals);
	fragColorLight = vec4(vertex_color.rgb, should_write_normals);
#else
    fragColorNormal = vec4(face_normals, should_write_normals);
#endif
}
