#ifdef CAN_BILINEAR_FILTER
#extension GL_ARB_texture_gather : enable
#endif

uniform sampler2D tex;
uniform sampler2D worldPalette;
uniform int tex_mode;
uniform int blend_mode;
in vec4 f_color;
in vec2 f_uv;
in vec3 f_coord;
out vec4 fragColor;

void main(void)
{
    vec4 sampled = texture(tex, f_uv);
    vec4 sampled_color = vec4(1.0, 1.0, 1.0, 1.0);
    vec4 vertex_color = f_color;
    float index = sampled.r;
    vec4 palval = texture(worldPalette, vec2(index, 0.5));

    if (tex_mode == 5
#ifndef CAN_BILINEAR_FILTER_16
    || tex_mode == 6
#endif
    )
    {
        if (sampled.r == 0.0 && sampled.g == 0.0 && sampled.b == 0.0 && blend_mode == 5)
            discard;
        sampled_color = vec4(sampled.b, sampled.g, sampled.r, sampled.a);
    }
#ifdef CAN_BILINEAR_FILTER_16
    else if (tex_mode == 6)
    {
        if (sampled.r == 0.0 && sampled.g == 0.0 && sampled.b == 0.0 && blend_mode == 5)
            discard;

        // Get texture size in pixels:
        vec2 colorTextureSize = vec2(textureSize(tex, 0));

        // Convert UV coordinates to pixel coordinates and get pixel index of top left pixel (assuming UVs are relative to top left corner of texture)
        vec2 pixCoord = f_uv * colorTextureSize - 0.5f;    // First pixel goes from -0.5 to +0.4999 (0.0 is center) last pixel goes from (size - 1.5) to (size - 0.5000001)
        vec2 originPixCoord = floor(pixCoord);              // Pixel index coordinates of bottom left pixel of set of 4 we will be blending

        // For Gather we want UV coordinates of bottom right corner of top left pixel
        vec2 gUV = (originPixCoord + 1.0f) / colorTextureSize;

        vec4 gR   = textureGather(tex, gUV, 0);
        vec4 gG   = textureGather(tex, gUV, 1);
        vec4 gB   = textureGather(tex, gUV, 2);
        vec4 gA   = textureGather(tex, gUV, 3);

        vec4 c00   = vec4(gB.w, gG.w, gR.w, gA.w);
        vec4 c01 = vec4(gB.x, gG.x, gR.x, gA.x);
        vec4 c11  = vec4(gB.y, gG.y, gR.y, gA.y);
        vec4 c10 = vec4(gB.z, gG.z, gR.z, gA.z);

        vec2 filterWeight = pixCoord - originPixCoord;
     
        // Bi-linear mixing:
        vec4 temp0 = mix(c01, c11, filterWeight.x);
        vec4 temp1 = mix(c00, c10, filterWeight.x);
        vec4 blendColor = mix(temp1, temp0, filterWeight.y);

        sampled_color = vec4(blendColor.r, blendColor.g, blendColor.b, 1.0);
    }
#endif

    else if (tex_mode == 1
#ifndef CAN_BILINEAR_FILTER
    || tex_mode == 2
#endif
    )

    {
        float transparency = 1.0;
        if (index == 0.0)
            discard;
        sampled_color = vec4(palval.r, palval.g, palval.b, transparency);
    }
#ifdef CAN_BILINEAR_FILTER
    else if (tex_mode == 2)
    {
        // Get texture size in pixels:
        vec2 colorTextureSize = vec2(textureSize(tex, 0));

        // Convert UV coordinates to pixel coordinates and get pixel index of top left pixel (assuming UVs are relative to top left corner of texture)
        vec2 pixCoord = f_uv * colorTextureSize - 0.5f;    // First pixel goes from -0.5 to +0.4999 (0.0 is center) last pixel goes from (size - 1.5) to (size - 0.5000001)
        vec2 originPixCoord = floor(pixCoord);              // Pixel index coordinates of bottom left pixel of set of 4 we will be blending

        // For Gather we want UV coordinates of bottom right corner of top left pixel
        vec2 gUV = (originPixCoord + 1.0f) / colorTextureSize;

        vec4 gIndex   = textureGather(tex, gUV);

        vec4 c00   = texture(worldPalette, vec2(gIndex.w, 0.5));
        vec4 c01 = texture(worldPalette, vec2(gIndex.x, 0.5));
        vec4 c11  = texture(worldPalette, vec2(gIndex.y, 0.5));
        vec4 c10 = texture(worldPalette, vec2(gIndex.z, 0.5));

        vec2 filterWeight = pixCoord - originPixCoord;
     
        // Bi-linear mixing:
        vec4 temp0 = mix(c01, c11, filterWeight.x);
        vec4 temp1 = mix(c00, c10, filterWeight.x);
        vec4 blendColor = mix(temp1, temp0, filterWeight.y);

        float transparency = 1.0;
        if (index == 0.0)
            discard;
        sampled_color = vec4(blendColor.r, blendColor.g, blendColor.b, transparency);
    }
#endif

    if (blend_mode == 5)
    {
        if (sampled_color.a < 0.1)
            discard;
    }
    fragColor = sampled_color * vertex_color;
}
