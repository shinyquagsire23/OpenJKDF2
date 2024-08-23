uniform mat4 mvp;

out vec2 f_uv;

void main()
{
    float x = -1.0 + float((gl_VertexID & 1) << 2);
    float y = -1.0 + float((gl_VertexID & 2) << 1);
	f_uv.x = (x+1.0)*0.5;
    f_uv.y = (y+1.0)*0.5;
    gl_Position = vec4(x, y, 0, 1);
}
