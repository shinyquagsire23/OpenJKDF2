in vec3 coord3d;
in vec4 v_color;
in vec2 v_uv;
uniform mat4 mvp;
out vec4 f_color;
out vec2 f_uv;
out vec3 f_coord;

void main(void)
{
    vec4 pos = mvp * vec4(coord3d, 1.0);
    pos.w = 1.0/(1.0-coord3d.z);
    pos.xyz *= pos.w;
    gl_Position = pos;
    f_color = v_color;
    f_uv = v_uv;
    f_coord = coord3d;
}
