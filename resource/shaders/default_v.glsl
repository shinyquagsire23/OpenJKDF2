//#define OBJECT_MOTION_BLUR

in vec3 coord3d;
in vec4 v_color;
in float v_light;
in vec2 v_uv;

in vec3 coordVS;

uniform mat4 mvp;
out vec4 f_color;
out float f_light;
out vec2 f_uv;
out vec3 f_coord;

#ifdef OBJECT_MOTION_BLUR
in vec3 v_motion;
out vec4 f_motion;
#endif

void main(void)
{
    vec4 pos = mvp * vec4(coord3d, 1.0);
    pos.w = 1.0/(1.0-coord3d.z);
    pos.xyz *= pos.w;
    gl_Position = pos;
    f_color = v_color.bgra;
    f_uv = v_uv;
    f_coord = coordVS;//coord3d;
    f_light = v_light;
#ifdef OBJECT_MOTION_BLUR
	if(v_motion.z > 0.0)
		f_motion = vec4(v_motion.xy * pos.w, 1.0, pos.w);
	else
		f_motion = vec4(0,0,0,1);
#endif
}
