uniform sampler2D tex;
uniform sampler2D tex2;
uniform sampler2D tex3;
uniform vec2 iResolution;
uniform float param1;
uniform float param2;
uniform float param3;
in vec4 f_color;
in vec2 f_uv;
in vec3 f_coord;
out vec4 fragColor;

#define PI 3.14159265359
#define AOradius 1.0
#define Samples 8.0

// --------------------------------------
// oldschool rand() from Visual Studio
// --------------------------------------
int   seed = 1;
void  srand(int s ) { seed = s; }
int   rand(void)  { seed=seed*0x343fd+0x269ec3; return (seed>>16)&32767; }
float frand(void) { return float(rand())/32767.0; }
// --------------------------------------
// hash by Hugo Elias
// --------------------------------------
int hash( int n ) { n=(n<<13)^n; return n*(n*n*15731+789221)+1376312589; }

// Color curve stuff idk
float gamma = 0.35;
float Cubic (float value) {
    
    // Possibly slightly faster calculation
    // when compared to Sigmoid
    
    if (value < 0.5)
    {
        return value * value * value * value * value * 16.0; 
    }
    
    value -= 1.0;
    
    return value * value * value * value * value * 16.0 + 1.0;
}

vec3 hemisphereVolumeRandPoint()
{
    vec3 p = vec3(frand() * 2.0 - 1.0,frand() * 2.0 - 1.0,frand());

    return normalize(p);
}

float depth(vec2 coord)
{
    vec2 uv = coord*vec2(iResolution.y/iResolution.x,1.0);
    return texture(tex, uv).z;
}

float SSAO(vec2 coord)
{
    float cd = depth(coord);
    float screenRadius = 0.5 * (AOradius / cd) / 0.53135;
    float li = 0.0;
    float count = 0.0;
    vec2 fragCoord = f_uv*iResolution.xy;

    vec3 normal = texture(tex2, f_uv).rgb;
    normal *= vec3(1.0, 1.0, -1.0);
    normal = normalize(normal);

    vec3 rvec = texture(tex3, (f_uv*iResolution.xy) / vec2(4.0)).rgb;

    vec3 tangent = normalize(rvec - normal * dot(rvec, normal));
    vec3 bitangent = cross(normal, tangent);
    mat3 tbn = mat3(tangent, bitangent, normal);

    vec3 kernels[128];
    for (int i = 0; i < int(Samples); i++)
    {
        kernels[i] = hemisphereVolumeRandPoint();// * frand();

        // Sample points should concentrate near the center of the hemisphere
        float scale = i / Samples;
        scale = mix(0.1f, 1.0f, scale * scale);
        kernels[i] *= scale;
    }

    ivec2 q = ivec2(fragCoord);
    srand( hash(q.x+hash(q.y+hash(1117 * int(param1)))));

    for(float i=0.0; i<Samples; i++)
    {
        vec3 p = kernels[int(i)];

        p *= frand();

        // Rotate the hemisphere
        p = tbn * p;

        vec2 sp = vec2(coord.x + p.x * screenRadius, coord.y + p.y * screenRadius);
        float d = depth(sp);
        float at = pow(length(p)-1.0, 2.0);
        li += step(cd + p.z * AOradius, d) * at;
        count += at;
    }
    return li / count;
}

void main(void)
{
    vec2 fragCoord = f_uv*iResolution.xy;

    // init random seed
    //ivec2 q = ivec2(fragCoord);
    srand( hash(1117 * int(param1)));

    // coordinate
    vec2 uv = fragCoord/(iResolution.xy);
    vec2 coord = fragCoord/(iResolution.y);

    vec4 sampled_color = vec4(1.0, 1.0, 1.0, 1.0);
    float d = depth(coord);
    vec3 ao = vec3(0.7) * SSAO(coord);
    vec3 color = mix(sampled_color.rgb, ao, 1.0 - smoothstep(0.0, 0.99, d*d/1e9));
    //color = mix(color, sampled_color.rgb, 1.0 - smoothstep(0.0, 0.1, d*d/15));
    
    // Color curve stuff, idk
    //color = pow(color,vec3(1.0/2.2)); // gamma
    color = vec3(Cubic(color.r),Cubic(color.g),Cubic(color.b));
    color = pow(color, vec3(gamma));

    //vec3 normal = texture(tex2, f_uv).rgb;
    //fragColor = vec4(normal, 1.0);
    fragColor = vec4(color, 1.0);
}