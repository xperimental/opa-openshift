FROM golang:1.16.5-alpine3.13 as builder

RUN apk add --update --no-cache ca-certificates tzdata git make bash && update-ca-certificates

ADD . /opt
WORKDIR /opt

RUN git update-index --refresh; make opa-openshift

FROM alpine:3.13 as runner

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /opt/opa-openshift /bin/opa-openshift

ARG BUILD_DATE
ARG VERSION
ARG VCS_REF
ARG DOCKERFILE_PATH

LABEL vendor="Observatorium" \
    name="observatorium/opa-openshift" \
    description="OPA-OpenShift proxy" \
    io.k8s.display-name="observatorium/opa-openshift" \
    io.k8s.description="OPA-OpenShift proxy" \
    maintainer="Observatorium <team-logging@redhat.com>" \
    version="$VERSION" \
    org.label-schema.build-date=$BUILD_DATE \
    org.label-schema.description="OPA-OpenShift proxy" \
    org.label-schema.docker.cmd="docker run --rm observatorium/opa-openshift" \
    org.label-schema.docker.dockerfile=$DOCKERFILE_PATH \
    org.label-schema.name="observatorium/opa-openshift" \
    org.label-schema.schema-version="1.0" \
    org.label-schema.vcs-branch=$VCS_BRANCH \
    org.label-schema.vcs-ref=$VCS_REF \
    org.label-schema.vcs-url="https://github.com/observatorium/opa-openshift" \
    org.label-schema.vendor="observatorium/opa-openshift" \
    org.label-schema.version=$VERSION

ENTRYPOINT ["/bin/opa-openshift"]
