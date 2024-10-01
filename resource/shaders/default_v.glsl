in vec3 coord3d;
in vec4 v_color;
in float v_light;
in vec2 v_uv;
in vec3 v_normal;

in vec3 coordVS;

uniform mat4 mvp;
out vec4 f_color;
out float f_light;
out vec2 f_uv;
out vec3 f_coord;
out vec3 f_normal;
out float f_depth;

void main(void)
{
    vec4 pos = mvp * vec4(coord3d, 1.0);
    pos.w = 1.0/(1.0-coord3d.z); // fixme: this doesn't match the projection matrix output AT ALL
    pos.xyz *= pos.w; // pretty sure the problem is z here
 	f_depth = pos.w / 128.0;
    gl_Position = pos;
    f_color = v_color.bgra;
    f_uv = v_uv;
#ifdef VIEW_SPACE_GBUFFER
    f_coord = coordVS;
#else
    f_coord = coord3d;
#endif
    f_light = v_light;
}
