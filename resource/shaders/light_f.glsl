uniform sampler2D texPos;
uniform sampler2D texNormal;
uniform sampler2D texColor;

uniform vec2 iResolution;

uniform vec3 lightColor;
uniform vec3 lightPosition;
uniform float lightAttenuation;

uniform vec3 colorEffects_tint;
uniform vec3 colorEffects_filter;
uniform float colorEffects_fade;
uniform vec3 colorEffects_add;

in vec4 f_color;
in vec2 f_uv;
in vec3 f_coord;
layout(location = 0) out vec4 fragColor;

vec2 oct_wrap(vec2 v)
{
	vec2 signs;
	signs.x = v.x >= 0.0 ? 1.0 : -1.0;
	signs.y = v.y >= 0.0 ? 1.0 : -1.0;
    return (1.0 - abs(v.yx)) * (signs);
}

vec3 decode_octahedron(vec2 p)
{
	p = p * 2.0 - 1.0;

	vec3 n;
    n.z = 1.0 - abs(p.x) - abs(p.y);
    n.xy = n.z >= 0.0 ? p.xy : oct_wrap( p.xy );
    return normalize(n);
}

void main(void)
{
    vec2 fragCoord = gl_FragCoord.xy;

    // coordinate
    vec2 uv = fragCoord/(iResolution.xy);
    vec2 coord = fragCoord/(iResolution.y);

	vec3 pos = texture(texPos, uv).xyz;
	vec3 normal = decode_octahedron(texture(texNormal, uv).xy);
	vec3 color = texture(texColor, uv).xyz;

	vec3 lightDir = lightPosition.xyz - pos.xyz;
	vec3 lightVec = normalize(lightDir);

	lightDir /= lightAttenuation;
	float att = clamp(1.0 + dot(lightDir, -lightDir), 0.0, 1.0);
	
	if(att < 0.00001)
		discard;
    
	vec3 result = color * lightColor * max(dot(normal, lightVec), 0.0);

	// probably all this shit needs to be a simple postfx pass instead of the mess in every shader
	result.rgb += colorEffects_add.rgb;

	vec3 tint = normalize(colorEffects_tint + 1.0) * sqrt(3.0);
	
    result.r *= tint.r;
    result.g *= tint.g;
    result.b *= tint.b;
	
    result.r *= colorEffects_fade;
    result.g *= colorEffects_fade;
    result.b *= colorEffects_fade;
	
    result.r *= colorEffects_filter.r;
    result.g *= colorEffects_filter.g;
    result.b *= colorEffects_filter.b;
	
    fragColor = vec4(result * att, 1.0);
}