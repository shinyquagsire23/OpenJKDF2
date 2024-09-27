uniform sampler2D texDepth;
uniform sampler2D texNormal;

uniform vec2 iResolution;

uniform uint   volumeFlags;
uniform vec3   volumePosition;
uniform float  volumeRadius;
uniform vec3   volumeColor;
uniform mat4x4 volumeInvMatrix;

uniform vec3 cameraLB;
uniform vec3 cameraLT;
uniform vec3 cameraRB;
uniform vec3 cameraRT;

in vec4 f_color;
in vec2 f_uv;
in vec3 f_coord;

void main(void)
{
	// null shader
}