# Kubernetes Agent Deployment

## Supported Kubernetes modes

| Mode | Use case | What it observes |
|---|---|---|
| DaemonSet | Node-level agent on all/some nodes | Node health, host-level observation, canary if hostNetwork enabled. |
| Canary Deployment | Simple service behind ingress/load balancer | Whether protected path reaches canary. |
| Sidecar | Specific app pod | Request/log context close to app. |
| Mirror collector | Cluster traffic copy if network supports it | Mirrored packet metadata. |

## Helm values

Default chart `apiUrl` is an HTTPS placeholder (`https://api.astranull.example`). Replace it with your tenant control-plane URL and ensure TLS terminates at ingress, service mesh, or the API service before agents register.

```yaml
apiUrl: https://api.astranull.example
mode: daemonset
agent:
  name: prod-node-agent
bootstrapTokenSecretName: astranull-bootstrap-token
persistence:
  type: hostPath
  hostPath: /var/lib/astranull
canaryListen:
  enabled: true
  port: 18080
securityContext:
  privileged: false
  capabilities: []
```

The chart mounts the bootstrap token as a file through a Kubernetes Secret and stores agent identity under `/var/lib/astranull`. Default persistence is `hostPath` so `identity.json` survives pod restarts; set `persistence.type: pvc` with `persistence.existingClaim` when cluster policy prefers managed storage. Use `emptyDir` only for disposable developer validation because the agent will need to re-register after restart.

## DaemonSet mode

Best when customer wants broad node deployment. It does not automatically prove every pod path unless the traffic is visible to the node agent or logs/mirror/canary are configured.

## Canary Deployment mode

Recommended production Kubernetes path:

```text
Ingress/CDN/WAF/LB -> Kubernetes Service -> AstraNull Canary Pod
```

This proves the protected route into the cluster.

## Sidecar mode

Best for critical app/service where customer wants request-level observation close to the application.

Requirements:

- app deployment update,
- resource limits,
- shared log volume or localhost listener if needed,
- clear port conflict avoidance.

## Completion criteria

Kubernetes support is complete when Helm can deploy DaemonSet, canary Deployment, and sidecar examples with clear placement explanations.
