package io.security.corespringsecurity.security.common;

import org.springframework.security.web.authentication.WebAuthenticationDetails;

import javax.servlet.http.HttpServletRequest;

public class FormWebAuthenticationDetails extends WebAuthenticationDetails {
    // Authentication 객체의 세부 정보 ( 로그인시 ID, PW 외의 파라미터값) 을 저장하기 위한 클래스
    // Authentication 객체의 Details 속성으로 저장된다.

    private String secretKey;
    // 객체별로 가지기 때문에 필드값을 가질수 있다


    public FormWebAuthenticationDetails(HttpServletRequest request) {
        super(request);
        secretKey = request.getParameter("secret_key");
    } // 생성자 메서드 HttpServletRequest 를 인자로 받아서 부모 객체의 변수로 넣고
    // 필요한 파라미터 들을 획득한다.

    public String getSecretKey() {
        return secretKey;
    } // 반환용 ㅁ[서ㅏㄷ,
}
