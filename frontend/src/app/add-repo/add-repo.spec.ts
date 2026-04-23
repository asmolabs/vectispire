import { ComponentFixture, TestBed } from '@angular/core/testing';

import { AddRepo } from './add-repo';

describe('AddRepo', () => {
  let component: AddRepo;
  let fixture: ComponentFixture<AddRepo>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [AddRepo],
    }).compileComponents();

    fixture = TestBed.createComponent(AddRepo);
    component = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
