package com.moodmate.domain.diary;

import com.moodmate.domain.diary.dto.DiaryMonthSummaryDto;
import com.moodmate.domain.diary.dto.DiaryRequestDto;
import com.moodmate.domain.diary.dto.DiaryResponseDto;
import com.moodmate.domain.diary.entity.Diary;
import com.moodmate.domain.diary.entity.DiaryEmotion;
import com.moodmate.domain.emotion.Emotion;
import com.moodmate.domain.user.entity.User;
import com.moodmate.domain.emotion.EmotionRepository;
import com.moodmate.domain.user.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.nio.file.AccessDeniedException;
import java.time.LocalDate;
import java.time.YearMonth;
import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional
public class DiaryService {

    private final DiaryRepository diaryRepository;
    private final EmotionRepository emotionRepository;
    private final UserRepository userRepository;

    public Long saveDiary(Long userId, DiaryRequestDto dto) {
        // 작성자 조회
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다."));

        // Diary 생성
        Diary diary = new Diary(dto.getContent(), dto.getDate(), user);

        // 3. 감정 리스트 처리
        for (DiaryRequestDto.EmotionRequest e : dto.getEmotions()) {
            Emotion emotion = emotionRepository.findByName(e.getName())
                    .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 감정입니다: " + e.getName()));

            DiaryEmotion diaryEmotion = new DiaryEmotion(emotion, e.getIntensity());
            diary.addDiaryEmotion(diaryEmotion); // 양방향 연결
        }

        // 4. 저장 (Cascade로 DiaryEmotion까지 저장됨)
        diaryRepository.save(diary);

        return diary.getId();
    }

    public DiaryResponseDto getDiaryByDate(Long userId, LocalDate date) {
        Diary diary = diaryRepository.findByUserIdAndDate(userId, date)
                .orElseThrow(() -> new IllegalArgumentException("해당 날짜의 일기가 없습니다."));
        return new DiaryResponseDto(diary);
    }

    public List<DiaryMonthSummaryDto> getDiarySummariesByMonth(Long userId, YearMonth yearMonth) {
        LocalDate start = yearMonth.atDay(1);
        LocalDate end = yearMonth.atEndOfMonth();

        List<Diary> diaries = diaryRepository.findByUserIdAndDateBetween(userId, start, end);

        return diaries.stream()
                .map(diary -> new DiaryMonthSummaryDto(
                        diary.getDate(),
                        diary.getDiaryEmotions().stream()
                                .map(de -> new DiaryMonthSummaryDto.EmotionDto(
                                        de.getEmotion().getName(),
                                        de.getIntensity()))
                                .toList()
                ))
                .toList();
    }



    public void updateDiary(Long diaryId, DiaryRequestDto dto, Long userId) throws AccessDeniedException {
        // 일기 조회
        Diary diary = diaryRepository.findById(diaryId)
                .orElseThrow(() -> new IllegalArgumentException("일기를 찾을 수 없습니다."));

        if (diary.getUser().getId() != userId) {
            throw new AccessDeniedException("해당 일기에 접근할 수 없습니다.");
        }

        // 일기 내용, 날짜 변경
        diary.setContent(dto.getContent());
        diary.setDate(dto.getDate());

        // 기존 감정 초기화
        diary.getDiaryEmotions().clear();

        // 새 감정들 추가
        for (DiaryRequestDto.EmotionRequest e : dto.getEmotions()) {
            Emotion emotion = emotionRepository.findByName(e.getName())
                    .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 감정입니다: " + e.getName()));
            DiaryEmotion de = new DiaryEmotion(emotion, e.getIntensity());
            diary.addDiaryEmotion(de);
        }
    }

    public void deleteDiary(Long diaryId, Long userId) throws AccessDeniedException {
        Diary diary = diaryRepository.findById(diaryId)
                .orElseThrow(() -> new IllegalArgumentException("일기를 찾을 수 없습니다."));

        if (diary.getUser().getId() != userId) {
            throw new AccessDeniedException("해당 일기에 접근할 수 없습니다.");
        }

        diaryRepository.delete(diary); // DiaryEmotion도 함께 삭제됨
    }

}
